# peda, pwndbg, ... are too slow. Waiting is annoying.
# And they are hard to debug android process because SIG33, SIG34, ...
# Here is a very simple implementation for memory stuff.
# usage:
# gdb -x gdb-memstuff.py
import gdb
import traceback


class Helper:
    @classmethod
    def u32(cls, exp, deref=False):
        exp = f'(unsigned int)({exp})'
        result = gdb.parse_and_eval(exp)
        if deref:
            result = gdb.parse_and_eval(f'*(unsigned int *){result}')
        return int(result)

    @classmethod
    def u64(cls, exp, deref=False):
        exp = f'(unsigned long)({exp})'
        result = gdb.parse_and_eval(exp)
        if deref:
            result = gdb.parse_and_eval(f'*(unsigned long *){result}')
        return int(result)

    @classmethod
    def write_bytes(cls, exp, data):
        block_idx = 0
        max_idx = len(data) // 0x1000
        while len(data) > 0:
            addr = f'(void *)({exp}) + ({block_idx * 0x1000})'
            if block_idx % 5 == 0:
                print(f'#({block_idx}/{max_idx}) write {addr}...')

            block = data[:0x1000]
            data_len = len(block)
            # first copy with null trailing
            first_block = ''.join(map(lambda x: f'\\x{x:x}', block[:-1]))
            cmd = f'set {{char[{data_len}]}}({addr}) = "{first_block}"'
            gdb.execute(cmd, False, False)
            # second copy last byte
            addr = f'(void *)({addr}) + {data_len - 1}'
            cmd = f'set {{char}}({addr}) = {block[-1]}'
            gdb.execute(cmd, False, False)

            data = data[0x1000:]
            block_idx += 1

    @classmethod
    def read_bytes(cls, exp, length):
        gdb.execute('set print repeat unlimited')
        gdb.execute('set print elements unlimited')
        data = gdb.parse_and_eval(f'*{{char []}}({exp})@{length}')
        result = data.format_string(format='x')
        result = eval(f'[{result[1:-1]}]')
        result = bytes(result)
        gdb.execute('set print elements 200')
        gdb.execute('set print repeat 10')
        return result

    @classmethod
    def read_str(cls, exp):
        result = b''
        cur = cls.read_bytes(exp, 256)
        offset = 256
        while b'\0' not in cur:
            result += cur
            cur = cls.read_bytes(f'((unsigned long){exp})+{offset}', 256)
            offset += 256
        result += cur[:cur.index(b'\0')]
        return result

    @classmethod
    def hook_run(cls, hook_list):
        '''
        hook_list = {
                0xa38d4: ['set $r0=0'],
                0x5bed8: ['set $r2=1'],
                }
        '''
        bps = [gdb.Breakpoint(f'*{bp}') for bp in hook_list]
        gdb.execute('c')
        while Helper.u64('$pc') in hook_list:
            for cmd in hook_list[Helper.u64('$pc')]:
                gdb.execute(cmd)
            gdb.execute('c')
        bps = [bp.delete() for bp in bps]


class MemStuff (gdb.Command):
    '''
    vmmap, xinfo
    TODO: telescope
    '''

    def __init__(self, name):
        self.name = name
        self.maps = []
        super(MemStuff, self).__init__(name, gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        if self.name == 'xinfo':
            self.xinfo(arg, from_tty)
        elif self.name == 'vmmap':
            self.vmmap(arg, from_tty)
        elif self.name == 'telescope':
            self.telescope(arg, from_tty)

    def telescope(self, arg, from_tty):
        '''telescope address size'''
        arg = arg.split(' ')
        arg += [''] * 2
        address, size = arg[:2]
        if size == '':
            size = '10'
        try:
            address = Helper.u64(address)
            size = Helper.u64(size)
        except Exception:
            print(f'your input: telescope {address} {size}')
            print('Usage: telescope address size')
            return
        # 64 bit
        for i in range(size):
            cur_addr = address + i * 8
            value = Helper.u64(address + i * 8, deref=True)
            result = f'{hex(cur_addr)}: {hex(value)} '
            try:
                data = gdb.execute(f'x/s {value}', False, True)
                data = (data.split(':')[1].strip())
                if data[0] == '"':
                    result += f'-> {data}'
            except Exception:
                '''invalid address'''
            print(result)

    def vmmap(self, arg, from_tty):
        self.maps_cache(arg, from_tty)
        result = []
        for start, end, *detail in self.maps:
            detail = f'{detail}'
            if arg:
                if arg in detail:
                    print(hex(start), hex(end), detail)
                    if not result:
                        result = [start, end, detail]
            else:
                print(hex(start), hex(end), detail)
        return result

    def maps_cache(self, arg, from_tty):
        if self.maps and not arg:
            return
        mappings = gdb.execute('i proc mappings', from_tty, True)
        if 'warning: unable to open /proc file' in mappings:
            print('adjust the address for qemu user-mode')
            # please add QEMU_GUEST_BASE=0x20000000 or -B 0x20000000 when running the qemu
            file = gdb.execute('i files', from_tty, True)
            file = file.split('\n', 1)[0].strip()
            file = file.split('"')[1].split('/')[-1]
            out = subprocess.check_output(f'ps a -o pid,args | grep qemu | grep {file}', shell=True)
            target_pid = []
            for proc in out.split(b'\n'):
                if not proc.strip() or b'grep' in proc:
                    continue
                target_pid.append((proc.strip().split(b' ')[0], proc))
            if len(target_pid) != 1:
                print(f'multiple target:\n{target_pid}')
                return
            target_pid = target_pid[0][0].decode()
            out = subprocess.check_output(f'cat /proc/{target_pid}/maps', shell=True)
            mappings = out.decode()
        result = []
        for line in mappings.split('\n'):
            line = line.strip()
            if line[:2] == '0x':
                buf = map(lambda x: x.strip(), line.strip().split(' '))
                buf = filter(lambda x: x, buf)
                buf = list(buf)
                buf[0] = int(buf[0], 0)
                buf[1] = int(buf[1], 0)
                result.append(buf[:])
            line = line.split(' ')
            if len(line) >= 5 and '-' in line[0]:
                offset = 0x20000000
                start, end = line[0].split('-')
                start, end = [int(start, 16), int(end, 16)]
                if start >= offset:
                    buf = [start - offset, end - offset]
                    extra = filter(lambda x: x, line[1:])
                    buf += list(extra)
                    result.append(buf[:])
        self.maps = result

    def xinfo(self, arg, from_tty):
        self.maps_cache('cache', from_tty)
        arg = Helper.u64(arg)
        print('xinfo', hex(arg), '...')
        result = []
        for start, end, *detail in self.maps:
            if arg >= start and arg < end:
                for _s, _e, *_d in self.maps:
                    if _d[-1] == detail[-1]:
                        print('---')
                        print(hex(_s), hex(_e), _d)
                        print(f'> offset = {hex(arg - _s)}')
                        if not result:
                            result += [_s, _e, _d]
                break
        return result


class Mycmd (gdb.Command):

    def __init__(self, name):
        self.name = name
        self.maps = []
        super(Mycmd, self).__init__(name, gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        try:
            f = getattr(self, self.name)
            f(arg, from_tty)
        except AttributeError:
            print('command not found')
        except Exception:
            traceback.print_exc()

    def rl(self, arg, from_tty):
        gdb.execute('source gdb-memstuff.py')


MemStuff('xinfo')
MemStuff('vmmap')
MemStuff('telescope')
Mycmd('rl')

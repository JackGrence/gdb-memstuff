# peda, pwndbg, ... are too slow. Waiting is annoying.
# And they are hard to debug android process because SIG33, SIG34, ...
# Here is a very simple implementation for memory stuff.
# usage:
# gdb -x gdb-memstuff.py
import gdb


class Helper:
    @classmethod
    def u32(cls, exp, deref=False):
        exp = f'(unsigned int)({exp})'
        result = gdb.parse_and_eval(exp)
        if deref:
            result = gdb.parse_and_eval(f'*(unsigned int *){result}')
        return result

    @classmethod
    def u64(cls, exp, deref=False):
        exp = f'(unsigned long)({exp})'
        result = gdb.parse_and_eval(exp)
        if deref:
            result = gdb.parse_and_eval(f'*(unsigned long *){result}')
        return result

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

    def vmmap(self, arg, from_tty):
        self.maps_cache(arg, from_tty)
        for start, end, *detail in self.maps:
            detail = f'{detail}'
            if arg:
                if arg in detail:
                    print(hex(start), hex(end), detail)
            else:
                print(hex(start), hex(end), detail)

    def maps_cache(self, arg, from_tty):
        if self.maps and not arg:
            return
        mappings = gdb.execute('i proc mappings', from_tty, True)
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
        self.maps = result

    def xinfo(self, arg, from_tty):
        self.maps_cache('cache', from_tty)
        arg = Helper.u64(arg)
        print('xinfo', hex(arg), '...')
        for start, end, *detail in self.maps:
            if arg >= start and arg < end:
                for _s, _e, *_d in self.maps:
                    if _d[-1] == detail[-1]:
                        print('---')
                        print(hex(_s), hex(_e), _d)
                        print(f'> offset = {hex(arg - _s)}')
                break


MemStuff("xinfo")
MemStuff("vmmap")

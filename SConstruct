COMPILER='gcc'

seg6_local_vrftable_test_c = """
#include <stdio.h>
#include <linux/seg6_local.h>

int
main()
{
        printf("%d", SEG6_LOCAL_VRFTABLE);
        return 0;
}
"""

def flags_to_string(flags):
	return ' ' + ' '.join(flags)

ldflags = [
        '-lnl-3',
        '-lnl-route-3',
        '-lnl-cli-3',
        '-lvppinfra',
        '-lvlibmemoryclient',
        '-lvppapiclient',
]

cflags = [ '-g', '-O0', '-Wall', '-std=gnu99', '-I/usr/local/include/libnl3' ]

AddOption('--vlibapi', action='store_true',
    help="Link vlibapi library", default=False)

env = Environment(CC = COMPILER)
conf = Configure(env)

result = conf.TryLink(seg6_local_vrftable_test_c, '.c')
if result:
	cflags.append('-DHAVE_SEG6_LOCAL_VRFTABLE')
print("Checking for SEG6_LOCAL_VRFTABLE... ", "yes" if result else "no")


env = conf.Finish()

if GetOption('vlibapi'):
	ldflags.append('-lvlibapi')

env['LINKCOM'] = '$LINK -o $TARGET $SOURCES $LINKFLAGS $__RPATH $_LIBDIRFLAGS $_LIBFLAGS'
env.Append(CFLAGS = flags_to_string(cflags))
env.Append(LINKFLAGS = flags_to_string(ldflags))
env.Program("lcp-addon", "main.c")

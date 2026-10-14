import faulthandler
import pathlib
import runpy
import sys
import traceback

root = pathlib.Path.cwd()
args = sys.argv[1:]
sys.path.insert(0, str(root))
sys.argv[0] = str(root / 'mach')
faulthandler.enable()
faulthandler.dump_traceback_later(45, repeat=True)
try:
    print('Initializing Mozilla command driver', flush=True)
    namespace = runpy.run_path(str(root / 'mach'))
    driver = namespace['check_and_get_mach'](str(root), args)
    print('Mozilla command driver initialized', flush=True)
    faulthandler.cancel_dump_traceback_later()
    status = driver.run(args)
    print(f'Mozilla command finished with status {status}', flush=True)
    sys.exit(status)
except BaseException:
    traceback.print_exc()
    raise
finally:
    faulthandler.cancel_dump_traceback_later()


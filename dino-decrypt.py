import argparse
from lib import stegosaurus

parser = argparse.ArgumentParser(description='Decrypts images into text files.')
parser.add_argument('input', help='Directory to find input.')
parser.add_argument('output', help='Directory to output images.')
# fb token - https://developers.facebook.com/tools/explorer/
parser.add_argument('token', help='Facebook token to use to login to FB.')

parser.add_argument('--verbose', action='store_true')
parser.add_argument('--clean', action='store_true')

args = parser.parse_args()

fb_img_cache = '.fbcache'

# check on input
if not os.path.exists(args.input):
    print("Input directory '%s' does not exist." % args.input)
    exit()

# clean
if args.clean:
    print('Cleaning target directory.')
    shutil.rmtree(args.output, ignore_errors=True)
    os.mkdir(args.output)

    print('Cleaning Facebook image cache.')
    shutil.rmtree(fb_img_cache, ignore_errors=True)

# perform action
stegosaurus.Encrypt()
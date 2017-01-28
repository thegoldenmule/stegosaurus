import argparse
import uuid
import shutil
import os
import facebook
from PIL import Image
import urllib
import struct
from steganography.steganography import Steganography

class FileRecord:
    relpath = ''
    bytelen = 0

    _totalbytesize = 0
    _buffer = []

    def __init__(self, relpath, bytecount):
        self.relpath = relpath
        self.bytelen = bytecount

    def total_byte_size(self):
        if 0 == self._totalbytesize:
            self._totalbytesize = 4 + self.payload_len()

        return self._totalbytesize

    def tobuffer(self):
        if 0 == len(self._buffer):
            length = self.payload_len()
            header = str(length).encode()

            f = open(self.relpath, 'rb')
            self._buffer = bytes(header + f.read())

        return self._buffer

    def payload_len(self):
        return len(bytearray(self.relpath)) + self.bytelen

class Encoder:

    # encrypts data
    @staticmethod
    def encrypt(args):
        # gather records
        totalinputbytes = 0
        records = []

        print('Analyzing inputs.')
        for root, dirs, files in os.walk(args.input):
            for file in files:
                relpath = os.path.join(root, file)
                bytecount = os.path.getsize(relpath)

                record = FileRecord(relpath, bytecount)
                records.append(record)

                if args.verbose:
                    print('>> Analyzing %s : %i total bytes in record.' % (relpath, record.total_byte_size()))

                totalinputbytes += record.total_byte_size()

        if len(records) == 0:
            print('No input found in %s.' % args.input)
            exit()

        # [RECORD LEN][PAYLOAD RELPATH][PAYLOAD]

        # see how much source material we have (width x height of all source combined)
        totalsourcebytes = 0

        if os.path.exists(args.source):
            for root, dirs, files in os.walk(args.source):
                for file in files:
                    if '.jpg' in file or '.jpeg' in file:
                        relpath = os.path.join(root, file)
                        jpg = Image.open(relpath)
                        totalsourcebytes += jpg.size[0] * jpg.size[1]
        else:
            os.mkdir(args.source)

        # download enough photos to cover byte length
        if totalsourcebytes < totalinputbytes:
            print('Downloading %s bytes of source images from Facebook.' % str(totalinputbytes - totalsourcebytes))

            graph = facebook.GraphAPI(access_token=args.token, version='2.2')

            response = graph.request('me/photos')

            for picture in response['data']:
                url = picture['picture']
                downloadpath = '%s.jpg' % os.path.join(args.source, str(uuid.uuid4()))

                if args.verbose:
                    print('>> Downloading %s...' % url)

                urllib.urlretrieve(url, downloadpath)
                jpg = Image.open(downloadpath)
                totalsourcebytes += jpg.size[0] * jpg.size[1]

                if totalsourcebytes > totalinputbytes:
                    break

        print("Adequate source material gathered.")

        # generate one time pad for the entire input at once, NOT piece by piece
        print('Generating one time pad: %i bytes.' % totalinputbytes)
        pad = os.urandom(totalinputbytes)

        # iterate over source material + generate record bytes
        absolutebyteindex = 0
        recordindex = 0
        recordbyteindex = 0
        imagebyteindex = 0

        for root, dirs, files in os.walk(args.source):
            for file in files:
                if '.jpg' in file or '.jpeg' in file:
                    relpath = os.path.join(root, file)
                    jpg = Image.open(relpath)

                    inputbytes = []
                    absolutebyteindexstart = absolutebyteindex
                    imagebyteindex = 0
                    imagebytecapacity = jpg.size[0] * jpg.size[1]

                    while imagebyteindex < imagebytecapacity:

                        # get the record we're currently working on
                        record = records[recordindex]

                        # see how much will fit in this image
                        numbytes = min(record.total_byte_size() - recordbyteindex, imagebytecapacity - imagebyteindex)

                        # copy to buffer
                        inputbytes += record.tobuffer()[recordbyteindex:recordbyteindex + numbytes]

                        # move indices
                        recordbyteindex += numbytes
                        imagebyteindex += numbytes
                        absolutebyteindex += numbytes

                        if recordbyteindex == record.total_byte_size():
                            if args.verbose:
                                print('\t>>Packed record %s.' % record.relpath)

                            recordindex += 1
                            recordbyteindex = 0

                            if recordindex >= len(records):
                                break

                    if args.verbose:
                        print('\t>>Writing output images for %s...' % relpath)

                    # we have the buffers, time to encode + write the data
                    imagepad = list(pad[absolutebyteindexstart:absolutebyteindex])
                    encryptedinputdata = [str(struct.unpack('B', x)[0] ^ struct.unpack('B', y)[0]) for (x, y) in zip(inputbytes, imagepad)]

                    # make sure paths exist
                    fullencodeddestpath = os.path.join(args.output, 'encoded', relpath)
                    encodeddestdir = os.path.dirname(fullencodeddestpath)

                    fullkeydestpath = os.path.join(args.output, 'key', relpath)
                    encodedkeydir = os.path.dirname(fullkeydestpath)

                    if not os.path.exists(encodeddestdir):
                        os.makedirs(encodeddestdir)

                    if not os.path.exists(encodedkeydir):
                        os.makedirs(encodedkeydir)

                    # write encrypted input
                    encryptedstring = ''.join(encryptedinputdata).decode()
                    Steganography.encode(relpath, fullencodeddestpath, encryptedstring)

                    if args.verbose:
                        print('\t>>Wrote %s...' % fullencodeddestpath)

                    # write pad
                    Steganography.encode(relpath, fullkeydestpath, str([struct.unpack('B', x)[0] for x in imagepad]))

                    if args.verbose:
                        print('\t>>Wrote %s...' % fullkeydestpath)

    @staticmethod
    def decypt(args):
        pass

# pngcrypt {encrypt, decrupt} [INPUT DIRECTORY] [OUTPUT DIRECTORY] [SOURCE DIRECTORY] [FACEBOOK TOKEN] (Optional)
parser = argparse.ArgumentParser(description='Encrpyts input files into images.')
parser.add_argument('action', choices=['encrypt', 'decrypt'])
parser.add_argument('input')
parser.add_argument('output')
parser.add_argument('source')

# fb token - https://developers.facebook.com/tools/explorer/
parser.add_argument('token', nargs='?')
parser.add_argument('--verbose', action='store_true')

args = parser.parse_args()

# check on input
if not os.path.exists(args.input):
    print("Input directory '%s' does not exist." % args.input)
    exit()

# clean
print('Cleaning target directory.')
shutil.rmtree(args.output, ignore_errors=True)
os.mkdir(args.output)

# perform action
if args.action == 'encrypt':
    Encoder.encrypt(args)
elif args.action == 'decrypt':
    Encoder.decrypt(args)
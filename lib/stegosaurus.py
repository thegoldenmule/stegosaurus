import uuid
import os
import facebook
from PIL import Image
import urllib
import struct
from steganography.steganography import Steganography

class FileRecord:
    in_path = ''
    out_path = ''

    begin = 0
    end = 0

    def __init__(self, in_path, out_path):
        self.in_path = in_path
        self.out_path = out_path

    def json(self):
        data = ''
        with open(self.in_path, 'r') as f:
            data = f.read()

        return '{"path":"%s","contents":"%s"}' % (self.out_path, data)

    def size(self):
        return 1
        return len('{"path":"%s","contents":""}' % self.out_path) + os.path.getsize(self.in_path)

def gather_records(input, output):
    records = []

    for root, dirs, files in os.walk(input):
        for file in files:
            inpath = os.path.join(root, file)
            outpath = inpath.replace(input, output, 1)

            record = FileRecord(inpath, outpath)
            records.append(record)

    return records

class RecordStream:
    header = '{"documents":['
    footer = ']}'
    size = 0
    index = 0

    def __init__(self, records):
        size = len(self.header)
        for record in records:
            record.begin = size
            size += record.size()
            record.end = size

        size += len(self.footer)

    def take(self, count):
        if count < 1:
            return ''

        if 0 == size:
            return ''

        if index >= size:
            return ''

        # clamp count
        count = min(count, size - index)

        # accumulator
        text = ''

        # deal with header
        header_size = len(self.header)
        if index < header_size:
            copy_size = min(len(self.header), count)
            text += self.header[index:index + copy_size]
            index += copy_size

        # deal with record data
        while len(text) < count:
            found_data = False

            # locate next record
            for record in records:
                if record.start <= index and record.end > index:
                    copylen = min(record.size(), count - index)

                    text += record.json()[index:index + copylen]
                    index += copylen

                    found_data = True
                    break

            if found_data is False:
                # end of records
                break

        # deal with footer
        if len(text) < count:
            count_remaining = count - len(text)
            copy_size = min(len(self.footer), count_remaining)
            text += self.footer[index:index + copy_size]
            index += copy_size

        return text
        
class Encoder:

    # encrypts data
    @staticmethod
    def encrypt(input, output, token, source):
        print('Performing encrypt.')

        # first, gather information on all the things we need to encrypt
        records = gather_records(input, output)

        if len(records) == 0:
            print('No input found in %s.' % input)
            exit()

        # create a stream
        stream = RecordStream(records)
        print('Stream created from %i records: %i bytes.' % (len(records), stream.size)

        ##
        ## Test
        ##
        print(stream.take(stream.size))
        return  

        # download enough photos to cover byte length
        if totalsourcebytes < totalinputbytes:
            print('Downloading %s bytes of source images from Facebook.' % str(totalinputbytes - totalsourcebytes))

            graph = facebook.GraphAPI(access_token=token, version='2.7')
            response = graph.request('me/photos')

            for picture in response['data']:
                id = picture['id']
                
                pictureResponse = graph.request('%s?fields=images' % id)
                pictureData = pictureResponse['images'][0]
                url = pictureData['source']

                downloadpath = '%s.jpg' % os.path.join(source, str(uuid.uuid4()))

                print('>> Downloading %s...' % url)

                urllib.urlretrieve(url, downloadpath)
                jpg = Image.open(downloadpath)
                totalsourcebytes += jpg.size[0] * jpg.size[1]

                if totalsourcebytes > totalinputbytes:
                    break

        print("Adequate source material gathered.")

        # iterate over source material + generate record bytes
        absolutebyteindex = 0
        recordindex = 0
        recordbyteindex = 0

        for root, dirs, files in os.walk(source):
            for file in files:
                if absolutebyteindex == totalinputbytes:
                    return

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
                            print('\t>>Packed record %s.' % record.relpath)

                            recordindex += 1
                            recordbyteindex = 0

                            if recordindex >= len(records):
                                break

                    print('\t>>Writing output images for %s...' % relpath)

                    # we have the buffers, time to encode + write the data
                    imagepad = list(pad[absolutebyteindexstart:absolutebyteindex])
                    encryptedinputdata = [str(struct.unpack('B', x)[0] ^ struct.unpack('B', y)[0]) for (x, y) in zip(inputbytes, imagepad)]

                    # make sure paths exist
                    fullencodeddestpath = os.path.join(output, 'encoded', relpath)
                    encodeddestdir = os.path.dirname(fullencodeddestpath)

                    fullkeydestpath = os.path.join(output, 'key', relpath)
                    encodedkeydir = os.path.dirname(fullkeydestpath)

                    if not os.path.exists(encodeddestdir):
                        os.makedirs(encodeddestdir)

                    if not os.path.exists(encodedkeydir):
                        os.makedirs(encodedkeydir)

                    # write encrypted input
                    encryptedstring = ''.join(encryptedinputdata).decode()
                    Steganography.encode(relpath, fullencodeddestpath, encryptedstring)

                    print('\t>>Wrote %s...' % fullencodeddestpath)

                    # write pad
                    Steganography.encode(relpath, fullkeydestpath, str([struct.unpack('B', x)[0] for x in imagepad]))

                    print('\t>>Wrote %s...' % fullkeydestpath)

    @staticmethod
    def decrypt(args):
        print('Performing decrypt.')
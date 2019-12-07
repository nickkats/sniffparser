"""
sniffparse V1
12/6/2019
Nick Katsantones

This script extracts the packets from a `K12 text file` exported by Wireshark.
There isn't much error handling, and it isn't optimized,  as such I don't recommend
this to be used in production, although you do you.

Example command line call:
python sniffparser.py ./blah.txt ./data.dat [-v]
"""
import re
import sys


def extract_packet_data(input_filename, output_filename, verbose=False):
    """
        Extracts the data from a 'K12 text file' which was exported by Wireshark.

    :param input_filename: the path to the 'K12 text file'
    :param output_filename: the path to the output file which will contain the raw binary
    :param verbose: if True, this will print out the current number of packets it has extracted
    """
    num_packets = 0
    with open(input_filename) as input_file:
        with open(output_filename, mode='wb') as output_file:
            was_header = False
            while True:
                # read the next line
                line = input_file.readline()

                # stop once we reach the end of the file
                if not line:
                    break

                table_header_match = re.match(r'^\+\-+\+\-+\+\-+\+$', line)

                # skip the header row
                if table_header_match is not None:
                    was_header = True
                    continue
                # skip the line _after_ the header row
                elif was_header:
                    was_header = False
                    continue
                # skip blank lines
                elif line is None or line.strip() == "":
                    continue
                else:
                    # there will be 2 leading and 1 trailing section delimited by the | char
                    parts = line.split('|')[2:-1]

                    # convert to binary, and write to file
                    binary_data = bytearray.fromhex(str.join('', parts))
                    output_file.write(binary_data)

                    # log if verbose
                    if verbose:
                        print('Parsed packet %d' % num_packets)
                    num_packets += 1


if __name__ == '__main__':
    args = sys.argv[1:]

    # handle an input and output filename
    if len(args) == 2:
        input_filename = args[0]
        output_filename = args[1]

        extract_packet_data(input_filename, output_filename)
    # input, output, and verbose flag
    elif len(args) == 3:
        input_filename = args[0]
        output_filename = args[1]
        verbose_flag = args[2]

        # fail if the verbose flag is strange
        if not verbose_flag == '-v':
            print('usage: python sniffparser.py InputFile OutputFile [-v]')
            exit(-1)

        extract_packet_data(input_filename, output_filename, True)
    else:
        print('usage: python sniffparser.py InputFile OutputFile [-v]')
        exit(-1)

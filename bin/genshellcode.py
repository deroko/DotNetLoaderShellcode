import  struct
import  argparse


buffx32 = open("dotnetloaderx32shellcode.bin", "rb").read();
buffx64 = open("dotnetloaderx64shellcode.bin", "rb").read();

dotnet =  open("WindowsFormsApplication1.exe", "rb").read();

parser = argparse.ArgumentParser()
parser.add_argument("--amd64", action="store_true", default=False, help="Use x64 shellcode...");
parser.add_argument("--i386",  action="store_true", default=False, help="Use x32 shellcode...");
parser.add_argument("outputfile");

args = parser.parse_args();

buff = "";

if args.amd64 == True:
        buff = buffx64;
elif args.i386 == True:
        buff = buffx32;
else:
        print("woops... wrong args...");
        exit(1);

buff += struct.pack("I", len(dotnet));
buff += dotnet;

with open(args.outputfile, "wb") as f:
        f.write(buff);
        f.flush();
                        



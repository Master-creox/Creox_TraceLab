import argparse, zipfile
from pathlib import Path

def main():
    parser=argparse.ArgumentParser(description="Restore a TraceLab backup into a separate directory")
    parser.add_argument("--archive",required=True)
    parser.add_argument("--destination",required=True)
    args=parser.parse_args(); dest=Path(args.destination).resolve(); dest.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(args.archive) as z:
        for member in z.infolist():
            target=(dest/member.filename).resolve()
            if dest not in target.parents and target!=dest: raise SystemExit("Unsafe archive path detected")
        z.extractall(dest)
    print(f"Restored into: {dest}")
if __name__=="__main__": main()

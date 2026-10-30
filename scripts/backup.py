import argparse, zipfile
from datetime import datetime
from pathlib import Path
from app.config import DATA_DIR

def main():
    parser=argparse.ArgumentParser(description="Back up TraceLab database and encrypted evidence")
    parser.add_argument("--output",default="backups")
    args=parser.parse_args()
    target=Path(args.output); target.mkdir(parents=True,exist_ok=True)
    archive=target/f"tracelab-{datetime.now().strftime('%Y%m%d-%H%M%S')}.zip"
    with zipfile.ZipFile(archive,"w",zipfile.ZIP_DEFLATED) as z:
        if DATA_DIR.exists():
            for item in DATA_DIR.rglob("*"):
                if item.is_file(): z.write(item,Path("data")/item.relative_to(DATA_DIR))
    print(f"Backup created: {archive}")
if __name__=="__main__": main()

import argparse
from app.database import init_db,get_db,utc_now
from app.security import hash_password

def main():
    parser=argparse.ArgumentParser(description="Create the first TraceLab administrator")
    parser.add_argument("--username",required=True)
    parser.add_argument("--password",required=True)
    args=parser.parse_args()
    init_db()
    try: hashed=hash_password(args.password)
    except ValueError as exc: raise SystemExit(str(exc))
    with get_db() as c:
        if c.execute("SELECT 1 FROM auth_users LIMIT 1").fetchone(): raise SystemExit("An account already exists. Sign in as admin to create additional users via the API.")
        c.execute("INSERT INTO auth_users(username,password_hash,role,created_at) VALUES(?,?,?,?)",(args.username,hashed,"admin",utc_now()))
    print(f"Admin account '{args.username}' created successfully.")
if __name__=="__main__": main()

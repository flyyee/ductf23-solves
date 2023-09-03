import os
for _ in range(16):
    os.system("python3 exp.py >> logs.txt")
    os.system("rm /tmp/bob*")
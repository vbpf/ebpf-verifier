import shutil
import os.path
import os
import re

with open("crab_deps.txt") as f:
    deps = [line.strip() for line in f]

try:
    os.mkdir("src/crab")
except:
    pass

for dep in deps:
    dst = "src/crab/" + os.path.basename(dep)
    shutil.copy(dep, dst)

def fix(folder, src):
    filename = folder + '/' + src
    if os.path.isdir(filename): return
    print(filename)
    with open(filename) as f:
        txt = f.read()
    
    txt = re.sub(r"<crab/.*?([a-zA-Z_]+.hp?p?)>", r'"crab/\1"', txt)

    with open(filename, 'w') as f:
        f.write(txt)

for src in os.listdir('src'):
    fix('src', src)
    
for src in os.listdir('src/crab'):
    fix('src/crab', src)
    

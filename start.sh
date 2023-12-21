DIR="output/"
 
if [ ! -d "$DIR" ]; then
  mkdir output
fi

python mitm.py

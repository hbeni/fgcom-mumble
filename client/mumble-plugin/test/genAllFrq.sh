#/!bin/bash
# Generates CSV list of all src and tgt frequencies
export LC_ALL=C.UTF-8
CURDIR=$(pwd)
DIR="$(dirname $0)"
cd "$DIR"

tool="./frqtest"
[[ ! -x $tool ]] && echo "$tool not found - did you already compile it? -> 'make test'!" && exit 1;

frq_start=118.000
frq_end=137.99

# Generate all 25kHz steps, old digit aliases (118.02; 118.05; etc)
outfile="$CURDIR/25kHz_smallalias.csv"
echo '"25kHz";"real";"channel";"realFromShort"' > $outfile
chn=0
echo -n "25kHz, two digits "
for i in $(seq $frq_start 0.025 $frq_end); do
    i=$(echo $i | sed 's/.$//')
    real=$($tool $i 0 |grep -E -o "realFrq\[1\] = '(.*)" |awk '{print $3;}' )
    real=$(echo $real | sed s/\'/\"/g)
    chan=$($tool $i 0 |grep -E -o "chan\[1\]    = '(.*)" |awk '{print $3;}' )
    chan=$(echo $chan | sed s/\'/\"/g)

    # also test shortened versions (123.1 must give the same as 123.10 or 123.100)
    shrt=$($tool $(echo -n $i | sed 's/0\+$//') 0 |grep -E -o "realFrq\[1\] = '(.*)" |awk '{print $3;}' )
    shrt=$(echo $shrt | sed s/\'/\"/g)

    echo "\"$i\";$real;$chan;$shrt" >> $outfile
    chn=$(echo "$chn + 1" |bc)
    echo -n "."
done
echo -e "\n$outfile written; $chn channels"


# Generate all 25kHz steps (118.00; 118.025; etc)
outfile="$CURDIR/25kHz_normal.csv"
echo '"25kHz";"real";"channel";"realFromShort"' > $outfile
chn=0
echo -n "25kHz, three digits "
for i in $(seq $frq_start 0.025 $frq_end); do
    real=$($tool $i 0 |grep -E -o "realFrq\[1\] = '(.*)" |awk '{print $3;}' )
    real=$(echo $real | sed s/\'/\"/g)
    chan=$($tool $i 0 |grep -E -o "chan\[1\]    = '(.*)" |awk '{print $3;}' )
    chan=$(echo $chan | sed s/\'/\"/g)

    # also test shortened versions (123.1 must give the same as 123.10 or 123.100)
    shrt=$($tool $(echo -n $i | sed 's/0\+$//') 0 |grep -E -o "realFrq\[1\] = '(.*)" |awk '{print $3;}' )
    shrt=$(echo $shrt | sed s/\'/\"/g)

    echo "\"$i\";$real;$chan;$shrt" >> $outfile
    chn=$(echo "$chn + 1" |bc)
    echo -n "."
done
echo -e "\n$outfile written; $chn channels"


# Generate all 8.33 frequencies
outfile="$CURDIR/8.33kHz_normal.csv"
echo '"8.33kHz";"real";"channel";"realFromShort"' > $outfile
chn=0
echo -n "8.33, three digits " 
for i in $(seq $frq_start 0.005 $frq_end); do
    echo $i | grep -q -E "20|45|70|95$"
    [[ $? -eq 0 ]] && continue   # skip certain invalid frequencies

    real=$($tool $i 0 |grep -E -o "realFrq\[1\] = '(.*)" |awk '{print $3;}' )
    real=$(echo $real | sed s/\'/\"/g)
    chan=$($tool $i 0 |grep -E -o "chan\[1\]    = '(.*)" |awk '{print $3;}' )
    chan=$(echo $chan | sed s/\'/\"/g)

    # also test shortened versions (123.1 must give the same as 123.10 or 123.100)
    shrt=$($tool $(echo -n $i | sed 's/0\+$//') 0 |grep -E -o "realFrq\[1\] = '(.*)" |awk '{print $3;}' )
    shrt=$(echo $shrt | sed s/\'/\"/g)

    echo "\"$i\";$real;$chan;$shrt" >> $outfile
    chn=$(echo "$chn + 1" |bc)
    echo -n "."
done
echo -e "\n$outfile written; $chn channels"

cd $CURDIR
echo "done."

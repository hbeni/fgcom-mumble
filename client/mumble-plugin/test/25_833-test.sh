#/!bin/bash
# Tests overlapping of 25kHz and 8.33kHz modes

export LC_ALL=C.UTF-8
CURDIR=$(pwd)
DIR="$(dirname $0)"
cd "$DIR"

tool="./frqtest"
[[ ! -x $tool ]] && echo "$tool not found - did you already compile it? -> 'make test'!" && exit 1;

frq_start=118.000
frq_end=137.99

# For all 25kHz steps (old digit aliases (118.02; 118.05; etc)) try to match nearby 8.33 channels
outfile="$CURDIR/25_833kHz-matching.csv"
echo '"frqA";"frqB";"sig25";"sig833"' > $outfile
chn=0
comb=0
for frq1 in $(seq $frq_start 0.025 $frq_end); do
    
    # Try 0.005 8.33 increments for the nearby channels
    # 25kHz should match 8.33 channel left and right of 25kHz carrier, but 8.33 should only match base frq
    # (except the "25kHz-base + .005" 8.33 alias of that base, which should match 100% -> for any given
    #  25kHz channel, we should have 2 8.33 channels matching)
    for offset in $(seq -0.025 0.005 0.025); do
        frq2=$(echo "$frq1 + $offset" | bc)
        res25=$($tool $frq1 $frq2 25 |grep -E -o "matchFilter = \(.+\) (.*)"  |awk '{print $4;}' | sed 's/...$//')
        res833=$($tool $frq1 $frq2 8.33 |grep -E -o "matchFilter = \(.+\) (.*)"  |awk '{print $4;}' | sed 's/...$//')
        echo "\"$frq1\";\"$frq2\";\"$res25\";\"$res833\"" >> $outfile
        
        comb=$(echo "$comb + 1" |bc)
    done
    
    
    # Try 0.005 8.33 increments for the 8.33 channels of this 25kHz segment
    # (only 8.33 correct channels should match)
    for frq1_off in $(seq 0.005 0.005 0.015); do
        frq1_833=$(echo "$frq1 + $frq1_off" | bc)
        for offset in $(seq 0.005 0.005 0.015); do
            frq2=$(echo "$frq1 + $offset" | bc)
            res833=$($tool $frq1_833 $frq2 8.33 |grep -E -o "matchFilter = \(.+\) (.*)"  |awk '{print $4;}' | sed 's/...$//')
            echo "\"$frq1_833\";\"$frq2\";\"-\";\"$res833\"" >> $outfile
            
            comb=$(echo "$comb + 1" |bc)
        done
    done
    # try to match the next 25kHz block frq_start
    frq2=$(echo "$frq1_833 + 0.010" | bc)
    res833=$($tool $frq1_833 $frq2 8.33 |grep -E -o "matchFilter = \(.+\) (.*)"  |awk '{print $4;}' | sed 's/...$//')
    echo "\"$frq1_833\";\"$frq2\";\"-\";\"$res833\"" >> $outfile
    comb=$(echo "$comb + 1" |bc)
    

    chn=$(echo "$chn + 1" |bc)
    echo -n "."
done
echo -e "\n$outfile written; $chn channels ($comb combinations)"



cd $CURDIR
echo "done."

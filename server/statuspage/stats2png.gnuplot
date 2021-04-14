# Plot the statstics file from the stats bot to PNG format
#
# invoke using: `gnuplot -e "filename = 'usage.stats'; timeselect_from = '20210401'; timeselect_to = '20210431'" stats2png.gnuplot > usage.png`

set terminal png
set autoscale
set datafile separator whitespace
set xdata time
set timefmt "%Y%m%d%H%M%S"
set xlabel "Time (UTC)"
set xrange [timeselect_from:timeselect_to]
set ylabel "Clients"
set format x "%Y-%m-%d\n%H:%M:%S"
set xtics rotate by 90 autofreq font ",8pt" nomirror right
set ytics autofreq font ",8pt"
set mytics 5
set yrange [0:*]
set grid back
set offsets 0, 0, 5, 0
plot filename using 1:2 title "Users" with lines lt rgb "#f00000", '' using 1:3 title "Broadcasts" with lines lt rgb "#0000f0"

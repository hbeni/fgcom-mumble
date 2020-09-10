# Plot the statstics file from the stats bot to PNG format
#
# invoke using: `cat usage.stats | gnuplot stats2png.gnuplot > usage.png`

set terminal png
set autoscale
set xdata time
set timefmt "%Y%m%d%H%M%S"
set xlabel "Time (UTC)"
set ylabel "Clients"
set format x "%Y-%m-%d\n%H:%M:%S"
set xtics rotate by 90 autofreq font ",8pt" nomirror right
set ytics autofreq font ",8pt"
set mytics 5
set yrange [0:*]
set grid back
set offsets 0, 0, 5, 0
plot '<cat' using 1:2 notitle with lines lt rgb "#f00000"

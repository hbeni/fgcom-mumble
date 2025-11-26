#!/bin/bash
# Proper background fuzzer execution
FUZZER_NAME=$1
DURATION_HOURS=${2:-12}
if [ -z "$FUZZER_NAME" ]; then
    echo "Usage: $0 <fuzzer_name> [duration_hours]"
    exit 1
fi
DURATION_SECONDS=$((DURATION_HOURS * 3600))
LOG_FILE="fuzzer_${FUZZER_NAME}.log"
PID_FILE="fuzzer_${FUZZER_NAME}.pid"
echo "Starting $FUZZER_NAME for $DURATION_HOURS hours..."
echo "Log file: $LOG_FILE"
echo "PID file: $PID_FILE"
nohup ./build/$FUZZER_NAME \
    -max_total_time=$DURATION_SECONDS \
    -error_exitcode=0 \
    -timeout=25 \
    -rss_limit_mb=4096 \
    -print_final_stats=1 \
    -artifact_prefix=crashes/ \
    -print_coverage=1 \
    corpus/ > "$LOG_FILE" 2>&1 &
echo $! > "$PID_FILE"
echo "Fuzzer started with PID: $!"
echo "Monitor with: tail -f $LOG_FILE"
echo "Stop with: kill \$(cat $PID_FILE)"

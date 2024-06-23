#!/bin/bash

for page in {1..200}
do
    echo "Processing page $page..."
    curl -s "https://www.freeproxy.world/?page=$page" | \
    grep -E "port" -B 3 | \
    sed -n '/<td>/,/<\/td>/p' | \
    grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}|port=[0-9]+' | \
    sed 's/<[^>]*>//g; s/^[^0-9]*//; s/[^0-9]*$//' | \
    awk '
    {
        if ($0 ~ /^[0-9]+$/) {
            port = $0
        } else {
            ip = $0
        }
        if (ip != "" && port != "") {
            print ip ":" port
            ip = ""
            port = ""
        }
    }' >> targets.txt
    
    sleep 2
done

echo "All pages processed. Results saved in targets.txt"
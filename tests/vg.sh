rm vg.log
valgrind -v --log-file=vg.log --leak-check=full --track-origins=yes --show-reachable=yes ./bin/mstunnel -f conf/mst.cfg

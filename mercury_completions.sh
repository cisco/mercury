
#-*- mode: shell-script;-*-

# this file contains a bash function that provides detailed command
# completion for mercury
#
# install in /usr/share/bash-completion/completions


_mercury()
{
    local cur prev opts
    _init_completion || return

    if [[ $prev == --capture ]]; then
        _available_interfaces
        return
    fi

    if [[ $prev == --user ]]; then
        _allowed_users
        return
    fi

    if [[ $prev == --directory ]]; then
        _filedir -d
        return
    fi

    if [[ $prev == --read ]]; then
        _filedir '@(pcap?(ng)|cap)?(.gz)'
        return
    fi

    if [[ $prev == --select ]]; then
        COMPREPLY=( $( compgen -W 'dhcp dns tls http quic ssh tcp tcp.message tls wireguard all none' -- "$cur") )
        return 0
    fi

    if [[ "$cur" == -* ]]; then
        COMPREPLY=( $( compgen -W '--capture --read --fingerprint --write --select --metadata --dns-json --certs-json --analysis --resources --nonselected-tcp-data --nonselected-udp-data --config --buffer --threads --user --directory --license --version --help' -- "$cur") )
        # COMPREPLY=( $( compgen -W '$( _parse_help "$1" )' -- "$cur" ) )
        return 0
    fi
}

complete -F _mercury mercury

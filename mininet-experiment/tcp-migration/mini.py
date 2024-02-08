import pickle
from mininet.link import TCLink, TCIntf
from mininet.node import Node, Intf
from mininet.clean import Cleanup
from mininet.cli import CLI
from mininet.net import Mininet
from mininet.node import RemoteController, Controller, OVSSwitch
from mininet.term import tunnelX11
from mininet.node import Host
from mininet.util import quietRun

def make_xterm(node: Node, title='Node', display=None, xterm_args=None, cmd='bash'):
    title = '%s: %s' % (title, node.name)
    if xterm_args is None:
        xterm_args = []
    display, tunnel = tunnelX11(node, display)
    if display is None:
        return []
    term = node.popen(['xterm', '-title', title, '-display', display, *xterm_args, '-e',
                       'env TERM=ansi %s' % cmd])
    return [tunnel, term] if tunnel else [term]


if __name__ == '__main__':
    # Cargar la instancia de Mininet desde el archivo
    with open('mininet_instance.pkl', 'rb') as file:
        net = pickle.load(file)



    net.stop()
    Cleanup.cleanup()
    

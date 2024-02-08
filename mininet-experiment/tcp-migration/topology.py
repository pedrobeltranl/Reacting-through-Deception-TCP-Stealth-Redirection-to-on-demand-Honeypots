from mininet.link import TCLink, TCIntf
from mininet.node import Node, Intf
from mininet.clean import Cleanup
from mininet.cli import CLI
from mininet.net import Mininet
from mininet.node import RemoteController, Controller, OVSSwitch
from mininet.term import tunnelX11


class OptionalRemoteController(RemoteController):
    def __init__(self, name, ip, port=None, **kwargs):
        Controller.__init__(self, name, ip=ip, port=port, **kwargs)

    def checkListening(self):
        """Ignore controller not accessible warning"""
        pass

    def stop(self):
        super(Controller, self).stop(deleteIntfs=True)


def create_network() -> Mininet:
    """
    Ryu and Snort on the same machine
    Ryu receives Snort alert packet via Unix Domain Socket

    +-----------------------------------+
    |              unixsock             |
    |   Snort  ----------------> Ryu    |
    |                 c0                |
    +--c0-eth0-----------------c0-eth1--+
          |                   10.0.1.1
          |                       |
          |                       |
          |                   10.0.1.10
    +--s1-eth4-----------------s1-eth5--+
    |                 s1                |
    |                                   |
    +--s1-eth1-----s1-eth2-----s1-eth3--+
          |           |           |
          |           |           |
       h1-eth0     h2-eth0     h3-eth0
      10.0.0.1    10.0.0.1    10.0.0.3
      +------+    +------+    +------+
      |  h1  |    |  h2  |    |  h3  |
      +------+    +------+    +------+
    """

    net = Mininet(controller=None, build=False, cleanup=True)
    
    
        
    net.addController('cc0', OptionalRemoteController, ip='10.0.1.1', port=6653)

    s1 = net.addSwitch('s1', cls=OVSSwitch, failmode='standalone')

    h1 = net.addHost('h1')
    h2 = net.addHost('h2')
    h3 = net.addHost('h3')
    c0 = net.addHost('c0')
    link_h1s1 = net.addLink(h1, s1, intfName1='h1-eth0', intfName2='s1-eth1')
    link_h2s1 = net.addLink(h2, s1, intfName1='h2-eth0', intfName2='s1-eth2')

    
    link_h3s1 = net.addLink(h3, s1, intfName1='h3-eth0', intfName2='s1-eth3', cls2=TCIntf, params2={'delay': '150ms'})
   
    link_c0p0s1 = net.addLink(c0, s1, intfName1='c0-eth0', intfName2='s1-eth4')  # snort-s1
    link_c0p1s1 = net.addLink(c0, s1, intfName1='c0-eth1', intfName2='s1-eth5')  # ryu-s1

    net.build()

    link_h1s1.intf1.config(mac='00:00:00:00:00:01', ip='10.0.0.1/24')
    link_h2s1.intf1.config(mac='00:00:00:00:00:01', ip='10.0.0.1/24')
    link_h3s1.intf1.config(mac='00:00:00:00:00:03', ip='10.0.0.3/24')

    link_c0p1s1.intf1.config(ip='10.0.1.1/24')
    link_c0p1s1.intf2.config(ip='10.0.1.10/24')

    c0.cmd('ifconfig c0-eth0 inet 0')
    c0.cmd('ifconfig c0-eth0 promisc')

    # disable flooding on s1-eth2
    # s1.cmd('ovs-ofctl mod-port s1 s1-eth2 no-flood')

    return net


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
    net = create_network()
    net.start()
    
        
    c0 = net.get('c0')
    s1 = net.get('s1')
    h1 = net.get('h1')
    h2 = net.get('h2')
    h3 = net.get('h3')
    # Obtener el nombre de la red virtual


    net.terms += make_xterm(c0, xterm_args=['-geometry', '120x25+50+50'])
    net.terms += make_xterm(s1, xterm_args=['-geometry', '120x25+50+50'])
    net.terms += make_xterm(c0, title='Snort',
                            cmd='snort -i c0-eth0 -A console -A unsock -l /tmp -c /etc/snort/rules/local.rules')
    net.terms += make_xterm(h1, xterm_args=['-geometry', '80x20+1050+50'])
    net.terms += make_xterm(h2, xterm_args=['-geometry', '80x20+1050+340'])
    net.terms += make_xterm(h3, xterm_args=['-geometry', '80x20+1050+630'])

    CLI(net)

    net.stop()
    Cleanup.cleanup()

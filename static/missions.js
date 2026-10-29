
(function () {
    'use strict';

    var CHAPTERS = [
        {
            id: 'ch1',
            number: 1,
            title: 'First contact',
            tagline: 'Open a capture, read the list, meet the three panes.',
            capture: 'sample',
            level: 'Beginner',
            badge: { id: 'novice', name: 'Packet Novice', icon: '◆' },
            missions: [
                {
                    id: 'first-packet',
                    title: 'Your first packet',
                    xp: 100,
                    brief: 'Every investigation starts the same way: pick a packet, read its summary, open its layers. Packet #3 is a DNS lookup leaving the client.',
                    learn: 'The viewer has three panes. The packet list is the summary of every frame. The packet details pane decodes the protocols inside the selected frame. The packet bytes pane shows the raw hex and ASCII on the wire. Click a row, then click a field to explore.',
                    hints: [
                        'Packet #3 is the third row: "Standard query 0x1a2b A example.com".',
                        'In the packet details pane, click any line such as "Query Name" to inspect a field.'
                    ],
                    tasks: [
                        { text: 'Select packet #3 in the packet list', select: { no: 3 } },
                        { text: 'Click any field in the packet details pane', field: true },
                        {
                            text: 'Which pane shows the decoded protocol layers?',
                            quiz: {
                                q: 'Which pane shows the decoded protocol layers?',
                                options: ['Packet list', 'Packet details', 'Packet bytes'],
                                answer: 1,
                                explain: 'The middle pane is the protocol tree: Frame, Ethernet II, IPv4, UDP, DNS and so on.'
                            }
                        }
                    ]
                },
                {
                    id: 'read-columns',
                    title: 'Read the columns',
                    xp: 110,
                    brief: 'The packet list is your map. Source, Destination, Protocol, Length and Info tell most of the story before you open a single layer.',
                    learn: 'In Wireshark the columns are configurable. Here, No. is the frame number, Time is relative to the start of the capture, Protocol is the highest decoded protocol, Length is the frame size, and Info is a one-line summary.',
                    hints: [
                        'Packet #2 is the ARP reply: "10.0.0.2 is at 02:00:00:00:00:02".',
                        'Packet #8 is the HTTP request. Look at the Destination port in its TCP layer (port 80).'
                    ],
                    tasks: [
                        { text: 'Select packet #2 — the ARP reply', select: { no: 2 } },
                        { text: 'Select packet #8 — the HTTP GET request', select: { no: 8 } },
                        {
                            text: 'Which destination port does the HTTP request use?',
                            quiz: {
                                q: 'Which destination port does packet #8 use?',
                                options: ['53', '80', '443'],
                                answer: 1,
                                explain: 'Port 80 is unencrypted HTTP. DNS uses 53 and HTTPS uses 443.'
                            }
                        }
                    ]
                },
                {
                    id: 'one-story',
                    title: 'One story, five packets',
                    xp: 120,
                    brief: 'A web page load is a sequence, not a single packet. Walk the same conversation the way an analyst would.',
                    learn: 'The classic order is: ARP (find the gateway), DNS (resolve the name), TCP handshake (SYN → SYN/ACK → ACK), HTTP request, HTTP response, then a TCP teardown with FIN packets.',
                    hints: [
                        'DNS query is #3, the TCP SYN is #5, the HTTP request is #8 and the response is #10.',
                        'Use the arrow keys to move through packets once you are in the list.'
                    ],
                    tasks: [
                        { text: 'Find the DNS query (#3)', select: { no: 3 } },
                        { text: 'Find the first TCP handshake packet (#5)', select: { no: 5 } },
                        { text: 'Find the HTTP request (#8)', select: { no: 8 } },
                        { text: 'Find the HTTP response (#10)', select: { no: 10 } },
                        {
                            text: 'What happens directly before the TCP handshake?',
                            quiz: {
                                q: 'What happens directly before the TCP handshake in this capture?',
                                options: ['DNS resolution', 'HTTP response', 'TCP teardown'],
                                answer: 0,
                                explain: 'The client resolved example.com to 203.0.113.10 with DNS, then connected to that address.'
                            }
                        }
                    ]
                },
                {
                    id: 'ping-pong',
                    title: 'Ping and reply',
                    xp: 100,
                    brief: 'Not every conversation uses TCP. ICMP is the small control protocol behind ping, and its request/reply pair is easy to spot.',
                    learn: 'ICMP has no ports. Its Type field describes the message: type 8 is an echo request, type 0 is an echo reply. Wireshark pairs them using the Identifier and Sequence Number, which is why packet #13 says "(request in 12)".',
                    hints: [
                        'Packets #12 and #13 are the ICMP pair. Filter icmp to keep both.',
                        'The reply is type 0. Select packet #13 and expand Internet Control Message Protocol.'
                    ],
                    tasks: [
                        { text: 'Select the ICMP echo request (#12)', select: { no: 12 } },
                        { text: 'Show only ICMP packets (icmp)', filter: { expr: ['icmp'], matches: 2 } },
                        { text: 'Select the ICMP echo reply (#13)', select: { no: 13 } },
                        {
                            text: 'Which ICMP type is an echo reply?',
                            quiz: {
                                q: 'Which ICMP type is an echo reply?',
                                options: ['0', '8', '3'],
                                answer: 0,
                                explain: 'Type 8 is the request, type 0 is the reply, and type 3 is destination unreachable.'
                            }
                        }
                    ]
                }
            ]
        },
        {
            id: 'ch2',
            number: 2,
            title: 'Display filters',
            tagline: 'Stop scrolling. Ask the capture a precise question.',
            capture: 'sample',
            level: 'Beginner',
            badge: { id: 'filter-pilot', name: 'Filter Pilot', icon: '⌁' },
            missions: [
                {
                    id: 'filter-protocol',
                    title: 'Filter by protocol',
                    xp: 120,
                    brief: 'The filter bar above the packet list accepts Wireshark display-filter syntax. Type a protocol name to keep only its packets.',
                    learn: 'A bare protocol name is a filter. `arp`, `dns` and `http` are three of the most useful. Invalid filters turn the bar red and keep the previous result set.',
                    hints: [
                        'Type the protocol name into the display filter bar at the top, then press Enter.',
                        'Each of these filters should leave exactly two packets: arp, dns, http.'
                    ],
                    tasks: [
                        { text: 'Show only ARP packets (arp)', filter: { expr: ['arp'], matches: 2 } },
                        { text: 'Show only DNS packets (dns)', filter: { expr: ['dns'], matches: 2 } },
                        { text: 'Show only HTTP packets (http)', filter: { expr: ['http'], matches: 2 } }
                    ]
                },
                {
                    id: 'filter-address',
                    title: 'Addresses and ports',
                    xp: 120,
                    brief: 'Filters can compare any field. Addresses use == and CIDR notation; ports use tcp.port or udp.port.',
                    learn: '`ip.addr` matches either endpoint. `ip.src` and `ip.dst` are directional. `tcp.port == 80` matches both directions of a conversation. Combine terms with `&&` (and) or `||` (or).',
                    hints: [
                        'The web server is 203.0.113.10.',
                        'Try ip.addr == 203.0.113.10, then tcp.port == 80, then ip.src == 10.0.0.1.'
                    ],
                    tasks: [
                        { text: 'Show traffic to or from 203.0.113.10', filter: { expr: ['ip.addr == 203.0.113.10'], matches: 12 } },
                        { text: 'Show only TCP port 80 traffic', filter: { expr: ['tcp.port == 80'], matches: 10 } },
                        { text: 'Show packets sent by 10.0.0.1', filter: { expr: ['ip.src == 10.0.0.1'], matches: 8 } }
                    ]
                },
                {
                    id: 'filter-logic',
                    title: 'Logic and negation',
                    xp: 130,
                    brief: 'Real questions need more than one condition. Combine terms and use negation to remove noise.',
                    learn: '`&&` (and) requires both sides, `||` (or) requires either side, and `!` (not) inverts a term. Parentheses group expressions: `!(arp || dns)` means "everything except ARP and DNS".',
                    hints: [
                        'A SYN packet has tcp.flags.syn == 1 and tcp.flags.ack == 0.',
                        'Negate a group: !(arp || dns). The HTTP response field is simply http.response.'
                    ],
                    tasks: [
                        { text: 'Show only connection attempts (SYN without ACK)', filter: { expr: ['tcp.flags.syn == 1 && tcp.flags.ack == 0'], matches: 1 } },
                        { text: 'Hide ARP and DNS: !(arp || dns)', filter: { expr: ['!(arp || dns)'], matches: 12 } },
                        { text: 'Show only HTTP responses', filter: { expr: ['http.response'], matches: 1 } },
                        {
                            text: 'Which operator means both conditions must be true?',
                            quiz: {
                                q: 'Which operator means both conditions must be true?',
                                options: ['&&', '||', '!'],
                                answer: 0,
                                explain: '`&&` is logical AND. `||` is OR and `!` is NOT.'
                            }
                        }
                    ]
                },
                {
                    id: 'filter-challenge',
                    title: 'Filter challenge',
                    xp: 120,
                    brief: 'Combine what you have learned: one filter that shows only the DNS response and the HTTP response.',
                    learn: 'Filters are expressions, so you can mix protocol fields from different protocols. `dns.flags.response == 1 || http.response` keeps two very different packets because both conditions are about responses.',
                    hints: [
                        'DNS responses have dns.flags.response == 1. HTTP responses have http.response.',
                        'Join the two conditions with || — there should be exactly two packets left.'
                    ],
                    tasks: [
                        { text: 'Show only the DNS response and the HTTP response', filter: { expr: ['dns.flags.response == 1 || http.response'], matches: 2 } },
                        {
                            text: 'Which filter shows only HTTP requests?',
                            quiz: {
                                q: 'Which filter shows only HTTP requests?',
                                options: ['http.request', 'http.response', 'tcp.port == 80'],
                                answer: 0,
                                explain: '`http.request` is a boolean field present only on request packets. Port 80 carries both directions.'
                            }
                        }
                    ]
                },
                {
                    id: 'port-story',
                    title: 'Ports tell a story',
                    xp: 120,
                    brief: 'Every conversation has two port numbers: the service port and a temporary client port. Learn to tell them apart before you read a single payload.',
                    learn: 'Servers listen on well-known ports: 53 for DNS, 80 for HTTP, 443 for HTTPS. Clients pick an ephemeral port (usually 49152 and above) for each conversation. `udp.port == 53` finds DNS in either direction, while `tcp.dstport == 80` keeps only packets heading to the web server. The port pair is the fastest way to identify who is serving and who is asking.',
                    hints: [
                        'DNS uses UDP port 53. The HTTP conversation uses TCP port 80.',
                        'Filter tcp.dstport == 80 to see only the client sending toward the web server — there should be six packets.'
                    ],
                    tasks: [
                        { text: 'Show DNS by service port: udp.port == 53', filter: { expr: ['udp.port == 53'], matches: 2 } },
                        { text: 'Show packets heading to the web server: tcp.dstport == 80', filter: { expr: ['tcp.dstport == 80'], matches: 6 } },
                        { text: 'Select the HTTP GET request (#8)', select: { no: 8 } },
                        { text: 'Select the HTTP response from port 80 (#10)', select: { no: 10 } },
                        {
                            text: 'Which side owns the service port?',
                            quiz: {
                                q: 'In packet #8 (49152 → 80), which port is the service port?',
                                options: ['49152, the client ephemeral port', '80, the web server port', 'Both ports are ephemeral'],
                                answer: 1,
                                explain: 'Port 80 is the well-known HTTP service port. 49152 is the client\'s temporary source port for this conversation.'
                            }
                        }
                    ]
                }
            ]
        },
        {
            id: 'ch3',
            number: 3,
            title: 'Protocol detective',
            tagline: 'DNS, TCP and TLS: read the fields that matter.',
            capture: 'academy',
            level: 'Intermediate',
            badge: { id: 'protocol-detective', name: 'Protocol Detective', icon: '⌘' },
            missions: [
                {
                    id: 'dns-detail',
                    title: 'DNS in detail',
                    xp: 140,
                    brief: 'This capture visits shop.example.com. Start with the name resolution that made the connection possible.',
                    learn: 'Each DNS query asks for a record type. A returns an IPv4 address, AAAA returns an IPv6 address, CNAME returns an alias and MX returns a mail server. The transaction ID ties a response to its query.',
                    hints: [
                        'Filter dns — there are six DNS packets: A and AAAA for shop.example.com plus the cdn.example.net lookup.',
                        'Packet #5 is the AAAA query. The Info column says "Standard query 0x1002 AAAA".'
                    ],
                    tasks: [
                        { text: 'Show only DNS traffic (dns)', filter: { expr: ['dns'], matches: 6 } },
                        { text: 'Select the AAAA query (#5)', select: { no: 5 } },
                        {
                            text: 'Which record type returns an IPv6 address?',
                            quiz: {
                                q: 'Which DNS record type returns an IPv6 address?',
                                options: ['A', 'AAAA', 'CNAME'],
                                answer: 1,
                                explain: 'A is IPv4, AAAA is IPv6, CNAME is an alias. This capture resolves 2001:db8::50 with AAAA.'
                            }
                        }
                    ]
                },
                {
                    id: 'tcp-handshake',
                    title: 'The TCP handshake',
                    xp: 140,
                    brief: 'Before any HTTPS request, TCP sets up a connection with three packets. Find them and prove you can tell them apart.',
                    learn: 'SYN asks to open a connection. SYN/ACK accepts it and acknowledges the client. ACK completes the handshake. Filter them with `tcp.flags.syn == 1`, then split on `tcp.flags.ack`.',
                    hints: [
                        'Filter tcp.flags.syn == 1 && tcp.flags.ack == 0 to see only the two opening SYNs (one per conversation).',
                        'Packet #8 is the SYN/ACK: it has both SYN and ACK set.'
                    ],
                    tasks: [
                        { text: 'Select the SYN/ACK of the HTTPS connection (#8)', select: { no: 8 } },
                        { text: 'Show only SYN packets without ACK', filter: { expr: ['tcp.flags.syn == 1 && tcp.flags.ack == 0'], matches: 2 } },
                        {
                            text: 'What is the second step of the handshake?',
                            quiz: {
                                q: 'What is the second step of the TCP handshake?',
                                options: ['SYN', 'SYN/ACK', 'FIN/ACK'],
                                answer: 1,
                                explain: 'Client SYN → server SYN/ACK → client ACK. The connection is open after the third packet.'
                            }
                        }
                    ]
                },
                {
                    id: 'tls-sni',
                    title: 'TLS and SNI',
                    xp: 150,
                    brief: 'Most traffic is encrypted, but the handshake still leaks useful metadata. Find the hostname in the TLS Client Hello.',
                    learn: 'TLS encrypts application data, but the Client Hello is sent in the clear and often includes Server Name Indication (SNI). It tells the server which certificate to present and gives analysts a hostname even when HTTP is invisible.',
                    hints: [
                        'Filter tls to see four records: Client Hello, Server Hello and two Application Data records.',
                        'Packet #10 is the Client Hello. Expand Transport Layer Security to find Server Name Indication.'
                    ],
                    tasks: [
                        { text: 'Show only TLS records (tls)', filter: { expr: ['tls'], matches: 4 } },
                        { text: 'Select the TLS Client Hello (#10)', select: { no: 10 } },
                        {
                            text: 'Which hostname is requested in the Client Hello?',
                            quiz: {
                                q: 'Which hostname is requested in the TLS Client Hello?',
                                options: ['cdn.example.net', 'shop.example.com', 'broken.example.com'],
                                answer: 1,
                                explain: 'The SNI extension carries shop.example.com, even though the HTTP payload is encrypted.'
                            }
                        }
                    ]
                },
                {
                    id: 'follow-stream',
                    title: 'Follow the stream',
                    xp: 130,
                    brief: 'Packets are fragments of a conversation. Follow Stream reassembles them so you can read the application data in order.',
                    learn: 'Right-click a TCP or UDP packet and choose Follow TCP/UDP Stream. Wireshark rebuilds the payload in both directions, which is much faster than reading packet by packet.',
                    hints: [
                        'Filter http.request so the GET /logo.png packet is easy to find.',
                        'Select the HTTP request (#22), then press the Follow button in the toolbar.'
                    ],
                    tasks: [
                        { text: 'Show only HTTP requests', filter: { expr: ['http.request'], matches: 1 } },
                        { text: 'Select the HTTP GET request (#22)', select: { no: 22 } },
                        { text: 'Follow the TCP stream of that conversation', dialog: ['Follow TCP Stream'] },
                        {
                            text: 'What does Follow Stream reassemble?',
                            quiz: {
                                q: 'What does Follow Stream reassemble for you?',
                                options: ['Only DNS answers', 'The application payload of a TCP/UDP conversation', 'The routing table'],
                                answer: 1,
                                explain: 'It stitches the payload bytes from every matching packet into one readable conversation.'
                            }
                        }
                    ]
                }
            ]
        },
        {
            id: 'ch4',
            number: 4,
            title: 'Traffic analyst',
            tagline: 'Zoom out: statistics turn packets into a story.',
            capture: 'academy',
            level: 'Intermediate',
            badge: { id: 'traffic-analyst', name: 'Traffic Analyst', icon: '▤' },
            missions: [
                {
                    id: 'hierarchy',
                    title: 'Protocol hierarchy',
                    xp: 120,
                    brief: 'Before reading packets one by one, ask what the capture is made of. The protocol hierarchy answers that in one window.',
                    learn: 'Statistics → Protocol Hierarchy shows which protocols appear and how much of the capture each one consumes. It is the fastest way to spot unexpected traffic.',
                    hints: [
                        'Open the Statistics menu and choose Protocol Hierarchy.',
                        'The dialog lists protocols by share of packets and bytes. TCP dominates this normal capture.'
                    ],
                    tasks: [
                        { text: 'Open Statistics → Protocol Hierarchy', dialog: ['Protocol Hierarchy'] },
                        {
                            text: 'Which transport protocol carries most of this capture?',
                            quiz: {
                                q: 'Which transport protocol carries most of this capture?',
                                options: ['UDP', 'TCP', 'ICMP'],
                                answer: 1,
                                explain: 'HTTPS and HTTP conversations dominate; DNS and ICMP are only a small fraction.'
                            }
                        }
                    ]
                },
                {
                    id: 'conversations',
                    title: 'Conversations and endpoints',
                    xp: 120,
                    brief: 'A conversation is a pair of addresses; an endpoint is a single address. Both views make it obvious who is talking to whom.',
                    learn: 'Statistics → Conversations groups packets by address/port pair and reports duration, packets and bytes. Statistics → Endpoints aggregates per host. Sort by bytes to find the heavy talker.',
                    hints: [
                        'Statistics → Conversations shows three conversations in this capture.',
                        'Statistics → Endpoints lists 10.0.0.5, 203.0.113.50, 198.51.100.20 and the DNS resolver.'
                    ],
                    tasks: [
                        { text: 'Open Statistics → Conversations', dialog: ['Conversations'] },
                        { text: 'Open Statistics → Endpoints', dialog: ['Endpoints'] },
                        {
                            text: 'Which host is the client in most conversations?',
                            quiz: {
                                q: 'Which host acts as the client in most conversations?',
                                options: ['203.0.113.50', '10.0.0.5', '10.0.0.53'],
                                answer: 1,
                                explain: '10.0.0.5 initiates the TLS and HTTP connections and sends the DNS queries.'
                            }
                        }
                    ]
                },
                {
                    id: 'io-graph',
                    title: 'The shape of traffic',
                    xp: 120,
                    brief: 'IO Graph plots packets or bytes over time. Bursts become visible: handshakes, downloads, keep-alives.',
                    learn: 'Statistics → IO Graph draws one series per filter. Set the interval to 0.1 s in a short capture to see each exchange separately. A spike is a burst; a flat line is idle time.',
                    hints: [
                        'Open Statistics → IO Graph. The default series is all packets.',
                        'Try a filter series such as tcp or dns to compare their shapes.'
                    ],
                    tasks: [
                        { text: 'Open Statistics → IO Graph', dialog: ['IO Graph'] },
                        {
                            text: 'What does a spike in the IO graph represent?',
                            quiz: {
                                q: 'What does a spike in the IO graph represent?',
                                options: ['A burst of traffic in that interval', 'A DNS server', 'A TCP reset'],
                                answer: 0,
                                explain: 'The graph buckets packets (or bytes) per interval. Tall bars mean more traffic in that slice of time.'
                            }
                        }
                    ]
                },
                {
                    id: 'make-it-yours',
                    title: 'Make it yours',
                    xp: 110,
                    brief: 'Colouring rules and columns turn a generic viewer into your workspace. Then mark a packet so you can find it again.',
                    learn: 'View → Coloring Rules applies display filters to row colours. View → Columns lets you add a column built from any field. Marking a packet (Ctrl+M) highlights it independently of filters, so it survives when you narrow the view.',
                    hints: [
                        'Both dialogs live in the View menu.',
                        'Select packet #22 and press Ctrl+M — or click the narrow mark column on the left.'
                    ],
                    tasks: [
                        { text: 'Open View → Coloring Rules', dialog: ['Coloring Rules'] },
                        { text: 'Open View → Columns', dialog: ['Column Preferences'] },
                        { text: 'Select the HTTP request (#22)', select: { no: 22 } },
                        { text: 'Mark packet #22 (Ctrl+M)', mark: [22] }
                    ]
                }
            ]
        },
        {
            id: 'ch5',
            number: 5,
            title: 'Incident responder',
            tagline: 'A broken capture. Find the four faults and close the case.',
            capture: 'trouble',
            level: 'Advanced',
            badge: { id: 'incident-responder', name: 'Incident Responder', icon: '⚑' },
            missions: [
                {
                    id: 'nxdomain',
                    title: 'NXDOMAIN',
                    xp: 150,
                    brief: 'A user reports that broken.example.com does not load. First question: did the name even resolve?',
                    learn: 'DNS response codes live in the RCODE field. 0 is success, 3 is NXDOMAIN (the name does not exist). Filter it with `dns.flags.rcode == 3`.',
                    hints: [
                        'Filter dns.flags.rcode == 3 — one response should remain.',
                        'Packet #4 is the response. Its Info reads "No such name".'
                    ],
                    tasks: [
                        { text: 'Show only NXDOMAIN responses', filter: { expr: ['dns.flags.rcode == 3'], matches: 1 } },
                        { text: 'Select the NXDOMAIN response (#4)', select: { no: 4 } },
                        {
                            text: 'What does NXDOMAIN mean?',
                            quiz: {
                                q: 'What does DNS RCODE 3 (NXDOMAIN) mean?',
                                options: ['The name does not exist', 'The server refused the query', 'The answer is cached'],
                                answer: 0,
                                explain: 'NXDOMAIN means the resolver has no record for that name. Further TCP attempts cannot succeed until the name is fixed.'
                            }
                        }
                    ]
                },
                {
                    id: 'connection-refused',
                    title: 'Connection refused',
                    xp: 150,
                    brief: 'The next connection attempt is rejected immediately. That leaves a very specific fingerprint in the capture.',
                    learn: 'A server that has no listener on a port answers a SYN with RST/ACK. That is a connection refused: no handshake, no application data. Filter it with `tcp.flags.rst == 1`.',
                    hints: [
                        'Filter tcp.flags.rst == 1. Only one packet matches in this capture.',
                        'Packet #6 is the RST/ACK from 203.0.113.99:443.'
                    ],
                    tasks: [
                        { text: 'Show only TCP resets (tcp.flags.rst == 1)', filter: { expr: ['tcp.flags.rst == 1'], matches: 1 } },
                        { text: 'Select the reset packet (#6)', select: { no: 6 } },
                        {
                            text: 'What does RST/ACK after a SYN usually mean?',
                            quiz: {
                                q: 'What does RST/ACK immediately after a SYN usually mean?',
                                options: ['The port is closed or refused', 'The transfer finished normally', 'The packet was retransmitted'],
                                answer: 0,
                                explain: 'The peer rejected the connection. In a web scenario this is often a service that is down or firewalled.'
                            }
                        }
                    ]
                },
                {
                    id: 'zero-window',
                    title: 'Zero window',
                    xp: 150,
                    brief: 'One HTTP request goes out, then the conversation stalls. Find the packet that explains the silence.',
                    learn: 'TCP advertises a receive window. A window of 0 means "stop sending, my buffer is full". The receiver will send a window update when its application reads data. Filter with `tcp.window == 0`.',
                    hints: [
                        'Filter tcp.window == 0. Packet #11 is the server ACK advertising a zero window.',
                        'Expert Information would also flag this as "TCP zero window".'
                    ],
                    tasks: [
                        { text: 'Show packets advertising a zero window', filter: { expr: ['tcp.window == 0'], matches: 1 } },
                        { text: 'Select the zero-window packet (#11)', select: { no: 11 } },
                        {
                            text: 'Why does the transfer stall?',
                            quiz: {
                                q: 'Why does the HTTP transfer stall after packet #11?',
                                options: ['The server buffer is full (zero window)', 'DNS failed', 'The client sent a reset'],
                                answer: 0,
                                explain: 'The server asks the client to stop sending because it cannot accept more data until its application drains the buffer.'
                            }
                        }
                    ]
                },
                {
                    id: 'port-unreachable',
                    title: 'Port unreachable',
                    xp: 150,
                    brief: 'A DNS query gets no answer, but the capture contains a different clue from the network itself.',
                    learn: 'ICMP type 3 means destination unreachable. Code 3 is port unreachable: the host exists but no service is listening on that UDP port. The original IP header is quoted inside the ICMP payload.',
                    hints: [
                        'Filter icmp.type == 3 — one packet matches.',
                        'Packet #13 quotes the UDP DNS query to 10.0.0.53:53.'
                    ],
                    tasks: [
                        { text: 'Show ICMP destination-unreachable packets', filter: { expr: ['icmp.type == 3'], matches: 1 } },
                        { text: 'Select the ICMP error (#13)', select: { no: 13 } },
                        {
                            text: 'Which ICMP code means "no service on that port"?',
                            quiz: {
                                q: 'Which ICMP unreachable code means no service is listening on the port?',
                                options: ['Code 1 — host unreachable', 'Code 3 — port unreachable', 'Code 4 — fragmentation needed'],
                                answer: 1,
                                explain: 'Code 3 says the host was reachable but the specific UDP port was not open.'
                            }
                        }
                    ]
                },
                {
                    id: 'tls-alert',
                    title: 'TLS alert',
                    xp: 150,
                    brief: 'One HTTPS endpoint does answer the handshake — and then immediately fails it. Find the alert.',
                    learn: 'TLS alerts are small records with a severity and a description. `tls.alert.severity` is 1 for warning and 2 for fatal. `tls.alert.description` 40 is handshake_failure.',
                    hints: [
                        'The handshake is on port 8443: packets #14–#18.',
                        'Filter tls.alert.description == 40 and select packet #18.'
                    ],
                    tasks: [
                        { text: 'Show the fatal handshake failure alert', filter: { expr: ['tls.alert.description == 40'], matches: 1 } },
                        { text: 'Select the TLS alert (#18)', select: { no: 18 } },
                        {
                            text: 'What is alert description 40?',
                            quiz: {
                                q: 'What is TLS alert description 40?',
                                options: ['handshake_failure', 'decompress_error', 'access_denied'],
                                answer: 0,
                                explain: 'handshake_failure means the peer could not negotiate a usable set of TLS parameters (cipher, version, certificate).'
                            }
                        }
                    ]
                },
                {
                    id: 'case-file',
                    title: 'Final case file',
                    xp: 250,
                    brief: 'Close the investigation. Summarise all faults with Expert Information, then mark the two packets you would attach to the ticket.',
                    learn: 'Expert Information aggregates warnings such as resets, zero windows and ICMP errors. Marking packets is a lightweight way to build an evidence list before you export or comment.',
                    hints: [
                        'Statistics → Expert Information lists RST, zero window and ICMP errors.',
                        'Select #6 and press Ctrl+M, then select #11 and press Ctrl+M again.'
                    ],
                    tasks: [
                        { text: 'Open Statistics → Expert Information', dialog: ['Expert Information'] },
                        { text: 'Select the reset packet (#6)', select: { no: 6 } },
                        { text: 'Mark packet #6 (Ctrl+M)', mark: [6] },
                        { text: 'Select the zero-window packet (#11)', select: { no: 11 } },
                        { text: 'Mark packet #11 (Ctrl+M)', mark: [11] },
                        {
                            text: 'Which statement best describes this capture?',
                            quiz: {
                                q: 'Which statement best describes this capture?',
                                options: [
                                    'A healthy capture with no faults',
                                    'Several independent failures: DNS, refused port, stalled transfer, unreachable service, TLS negotiation',
                                    'Only a TLS certificate problem'
                                ],
                                answer: 1,
                                explain: 'Each mission found a different fault. Real incidents often contain several independent problems at once.'
                            }
                        }
                    ]
                }
            ]
        }
    ];

    CHAPTERS.push({
        id: 'ch6',
        number: 6,
        title: 'Transport troubleshooter',
        tagline: 'Retransmissions, duplicate ACKs and fragments: why transfers crawl.',
        capture: 'advanced',
        level: 'Advanced',
        badge: { id: 'transport-medic', name: 'Transport Medic', icon: '⊞' },
        missions: [
            {
                id: 'retransmission',
                title: 'The duplicate segment',
                xp: 180,
                brief: 'A transfer feels slow. Packets #10 and #11 carry the same bytes. Prove it, then find both copies with one filter.',
                learn: 'TCP numbers every byte. A retransmission repeats a sequence number and its payload because the sender did not see an ACK in time. Loss, a delayed ACK or a spurious timeout can all trigger it. The receiver keeps the first copy and discards the duplicate.',
                hints: [
                    'Compare #10 and #11 — both carry Seq=99 in Wireshark\'s relative view and the same 82 bytes of payload.',
                    'The viewer shows the raw sequence number. Filter tcp.seq == 3099 to keep both copies.'
                ],
                tasks: [
                    { text: 'Select the original GET segment (#10)', select: { no: 10 } },
                    { text: 'Select the repeated segment (#11)', select: { no: 11 } },
                    { text: 'Filter both copies: tcp.seq == 3099', filter: { expr: ['tcp.seq == 3099'], matches: 2 } },
                    {
                        text: 'What does a retransmission repeat?',
                        quiz: {
                            q: 'What does a TCP retransmission repeat?',
                            options: ['A sequence number and its payload', 'A DNS transaction ID', 'An ARP request'],
                            answer: 0,
                            explain: 'The sender reuses the same sequence number and bytes because it has not received an acknowledgment covering them yet.'
                        }
                    }
                ]
            },
            {
                id: 'dup-acks',
                title: 'Duplicate ACK storm',
                xp: 180,
                brief: 'The receiver keeps repeating the same acknowledgment. That is not noise: it is a request for one missing piece.',
                learn: 'When a receiver sees out-of-order data, it re-ACKs the last contiguous byte. Three duplicate ACKs are the classic trigger for fast retransmit: the sender resends the missing segment without waiting for a timeout.',
                hints: [
                    'Packets #12–#15 all acknowledge the same byte. Filter tcp.ack == 3181 && tcp.len == 0 to keep only the ACK-only packets.',
                    'Select packet #14, one of the duplicate ACKs.'
                ],
                tasks: [
                    { text: 'Filter the repeated acknowledgment: tcp.ack == 3181 && tcp.len == 0', filter: { expr: ['tcp.ack == 3181 && tcp.len == 0'], matches: 4 } },
                    { text: 'Select a duplicate ACK (#14)', select: { no: 14 } },
                    {
                        text: 'What do three duplicate ACKs tell the sender?',
                        quiz: {
                            q: 'What do three duplicate ACKs usually tell the sender?',
                            options: ['A segment is missing, so retransmit it', 'The connection is encrypted', 'The DNS answer expired'],
                            answer: 0,
                            explain: 'The receiver is still waiting for the same missing byte. Repeated ACKs are the signal for fast retransmit.'
                        }
                    }
                ]
            },
            {
                id: 'fragments',
                title: 'Fragments and offsets',
                xp: 190,
                brief: 'A 4,400-byte UDP datagram cannot fit in one Ethernet frame. Three IPv4 fragments carry it, and only one has the transport header.',
                learn: 'IPv4 fragmentation splits a datagram into pieces with a fragment offset. The first piece (offset 0) carries the UDP or TCP header. Later pieces have a non-zero offset, and the last piece clears the More Fragments flag. Reassembly happens at the destination.',
                hints: [
                    'Packets #21–#23 share the same IP ID. #21 has offset 0; #22 and #23 are later pieces.',
                    'Filter ip.frag_offset > 0 to keep only the non-first fragments.'
                ],
                tasks: [
                    { text: 'Select the first fragment (#21)', select: { no: 21 } },
                    { text: 'Show the non-first fragments: ip.frag_offset > 0', filter: { expr: ['ip.frag_offset > 0'], matches: 2 } },
                    { text: 'Select the last fragment (#23)', select: { no: 23 } },
                    {
                        text: 'Which fragment carries the UDP header?',
                        quiz: {
                            q: 'Which IPv4 fragment carries the UDP header?',
                            options: ['The first fragment (offset 0)', 'The last fragment only', 'Every fragment carries a copy'],
                            answer: 0,
                            explain: 'The transport header is at the start of the datagram, so it travels in the offset-0 fragment. Later fragments contain only payload bytes.'
                        }
                    }
                ]
            },
            {
                id: 'slow-transfer',
                title: 'Diagnose the slow transfer',
                xp: 220,
                brief: 'Put the symptoms together with statistics, then build an evidence list by marking both copies of the repeated segment.',
                learn: 'A retransmission does not change the destination or the protocol. Its cost is time and bandwidth: the network carries bytes the receiver already has, and the application waits for the missing sequence to be filled. Statistics views show the stall; marks preserve the evidence across filters.',
                hints: [
                    'Statistics → IO Graph shows where traffic stops and restarts.',
                    'Select #10 and press Ctrl+M, then select #11 and press Ctrl+M.'
                ],
                tasks: [
                    { text: 'Open Statistics → IO Graph', dialog: ['IO Graph'] },
                    { text: 'Open Statistics → Conversations', dialog: ['Conversations'] },
                    { text: 'Select the original segment (#10)', select: { no: 10 } },
                    { text: 'Mark packet #10 (Ctrl+M)', mark: [10] },
                    { text: 'Select the retransmission (#11)', select: { no: 11 } },
                    { text: 'Mark packet #11 (Ctrl+M)', mark: [11] },
                    {
                        text: 'What is the main cost of a retransmission?',
                        quiz: {
                            q: 'What is the main cost of retransmitting a TCP segment?',
                            options: ['Extra delay and duplicate bytes on the wire', 'A changed destination address', 'TLS is disabled'],
                            answer: 0,
                            explain: 'The connection still works, but the transfer wastes time and bandwidth carrying a second copy of data the receiver may already have.'
                        }
                    }
                ]
            }
        ]
    });

    CHAPTERS.push({
        id: 'ch7',
        number: 7,
        title: 'Threat hunter',
        tagline: 'One capture, five leads: spoofing, scanning, DNS tunnelling and command-and-control.',
        capture: 'threat',
        level: 'Expert',
        badge: { id: 'threat-hunter', name: 'Threat Hunter', icon: '☣' },
        missions: [
            {
                id: 'arp-spoof',
                title: 'The gateway imposter',
                xp: 200,
                brief: 'Two hosts claim the same gateway address. Find the lie in the ARP traffic before it poisons the victim\'s cache.',
                learn: 'ARP has no authentication. Any host can answer "10.0.0.1 is at my MAC". A duplicate gateway IP with a new MAC is a classic ARP-spoofing signature and enables man-in-the-middle traffic capture.',
                hints: [
                    'Filter arp — there are three packets: a request, the real reply and a second reply.',
                    'The attacker MAC is 02:00:00:00:00:66. Filter arp.src.hw_mac == 02:00:00:00:00:66.'
                ],
                tasks: [
                    { text: 'Show all ARP traffic (arp)', filter: { expr: ['arp'], matches: 3 } },
                    { text: 'Select the spoofed ARP reply (#3)', select: { no: 3 } },
                    { text: 'Show the attacker\'s ARP reply by MAC', filter: { expr: ['arp.src.hw_mac == 02:00:00:00:00:66'], matches: 1 } },
                    {
                        text: 'Why is packet #3 suspicious?',
                        quiz: {
                            q: 'Why is the third ARP packet suspicious?',
                            options: ['The gateway IP is announced from an unexpected MAC', 'It uses UDP instead of TCP', 'It contains a TLS alert'],
                            answer: 0,
                            explain: 'The real gateway already answered. A second host claiming 10.0.0.1 can redirect the victim\'s traffic through the attacker.'
                        }
                    }
                ]
            },
            {
                id: 'port-scan',
                title: 'Knock, knock',
                xp: 200,
                brief: 'A single source touches nine ports in a few milliseconds. Identify the scan and the response pattern.',
                learn: 'A vertical port scan sends a SYN to many ports on one host. Closed ports answer with RST/ACK, open ports would complete the handshake. The pattern of many destinations and immediate resets is the fingerprint.',
                hints: [
                    'The scanner is 10.0.0.66. Filter ip.src == 10.0.0.66 && tcp.flags.syn == 1 && tcp.flags.ack == 0.',
                    'The target answers every attempt with RST/ACK. Filter ip.dst == 10.0.0.66 && tcp.flags.rst == 1.'
                ],
                tasks: [
                    { text: 'Show SYNs sent by 10.0.0.66', filter: { expr: ['ip.src == 10.0.0.66 && tcp.flags.syn == 1 && tcp.flags.ack == 0'], matches: 9 } },
                    { text: 'Select the first scan attempt (#4)', select: { no: 4 } },
                    { text: 'Show resets returned to the scanner', filter: { expr: ['ip.dst == 10.0.0.66 && tcp.flags.rst == 1'], matches: 9 } },
                    {
                        text: 'What does this pattern indicate?',
                        quiz: {
                            q: 'What does one host sending SYNs to nine ports in a burst indicate?',
                            options: ['A port scan', 'A normal TLS handshake', 'A DNS zone transfer'],
                            answer: 0,
                            explain: 'Trying many ports on one target in a short window is reconnaissance. The RST/ACK replies show the ports were closed.'
                        }
                    }
                ]
            },
            {
                id: 'dns-tunnel',
                title: 'DNS with a payload',
                xp: 190,
                brief: 'The DNS queries look wrong: TXT records with long encoded labels. Follow the naming pattern.',
                learn: 'DNS is rarely blocked, which makes it attractive for tunnelling. Long, high-entropy labels and unusual record types such as TXT can hide commands or stolen data inside otherwise normal-looking queries.',
                hints: [
                    'Filter dns.qry.type == 16 to see the TXT lookups.',
                    'Both names end in evil.example. Filter dns.qry.name contains evil.'
                ],
                tasks: [
                    { text: 'Show DNS TXT queries and responses', filter: { expr: ['dns.qry.type == 16'], matches: 4 } },
                    { text: 'Select the first TXT query (#22)', select: { no: 22 } },
                    { text: 'Show names containing "evil"', filter: { expr: ['dns.qry.name contains evil'], matches: 4 } },
                    {
                        text: 'Why are these DNS queries suspicious?',
                        quiz: {
                            q: 'Why are these DNS queries suspicious?',
                            options: ['TXT records carry long encoded labels to an unknown domain', 'They use port 53', 'They contain a TCP handshake'],
                            answer: 0,
                            explain: 'Port 53 is normal; the signal is the record type and the encoded labels. DNS tunnelling hides data in exactly this shape.'
                        }
                    }
                ]
            },
            {
                id: 'malicious-upload',
                title: 'The upload',
                xp: 190,
                brief: 'The victim sends a binary payload to an unfamiliar host over HTTP. Find the request and read its shape.',
                learn: 'A POST to a PHP endpoint with a binary content type is a common upload pattern. When the destination is unknown and the payload starts with an executable header, treat it as possible staging or exfiltration.',
                hints: [
                    'Filter http.request.method == "POST". Only one packet matches.',
                    'Packet #29 is the upload. Its Host header is update.bad-cdn.example.'
                ],
                tasks: [
                    { text: 'Show only HTTP POST requests', filter: { expr: ['http.request.method == "POST"'], matches: 1 } },
                    { text: 'Select the POST request (#29)', select: { no: 29 } },
                    {
                        text: 'What makes this request worth escalating?',
                        quiz: {
                            q: 'What makes the POST request worth escalating?',
                            options: ['A binary upload to an unknown host', 'It uses HTTP instead of HTTPS', 'It has a Content-Length header'],
                            answer: 0,
                            explain: 'The combination of an unfamiliar destination, a binary body and an executable-looking payload is far more important than the missing TLS alone.'
                        }
                    }
                ]
            },
            {
                id: 'c2-sni',
                title: 'Command-and-control SNI',
                xp: 190,
                brief: 'Encrypted traffic still leaks the hostname. One TLS Client Hello asks for a domain that looks like a fake update service.',
                learn: 'SNI is sent before encryption begins. Even when the payload is invisible, the requested hostname can reveal command-and-control infrastructure. Compare it with the domains observed in DNS and HTTP.',
                hints: [
                    'Filter tls.handshake.extensions_server_name == "update.bad-cdn.example".',
                    'Packet #34 is the Client Hello. The same domain appeared in the HTTP Host header.'
                ],
                tasks: [
                    { text: 'Show the suspicious TLS SNI', filter: { expr: ['tls.handshake.extensions_server_name == "update.bad-cdn.example"'], matches: 1 } },
                    { text: 'Select the Client Hello (#34)', select: { no: 34 } },
                    {
                        text: 'What does the SNI reveal here?',
                        quiz: {
                            q: 'What does the TLS SNI reveal in this capture?',
                            options: ['The hostname the client is trying to reach', 'The user\'s password', 'The full HTTP response body'],
                            answer: 0,
                            explain: 'SNI is cleartext metadata. It links the encrypted session to update.bad-cdn.example even though the application data is unreadable.'
                        }
                    }
                ]
            },
            {
                id: 'threat-case',
                title: 'Final threat case',
                xp: 280,
                brief: 'Close the investigation. Open Expert Information, then attach the two strongest packets to the ticket.',
                learn: 'A good incident report connects evidence across protocols: the spoofed ARP reply explains redirection, the scan shows reconnaissance, the DNS and HTTP traffic show staging or exfiltration, and the SNI identifies infrastructure. Mark the packets you would hand to the next analyst.',
                hints: [
                    'Statistics → Expert Information summarises resets, SYNs and other warnings.',
                    'Select #3 and press Ctrl+M, then select #29 and press Ctrl+M.'
                ],
                tasks: [
                    { text: 'Open Statistics → Expert Information', dialog: ['Expert Information'] },
                    { text: 'Select the spoofed ARP reply (#3)', select: { no: 3 } },
                    { text: 'Mark the ARP spoof (#3)', mark: [3] },
                    { text: 'Select the HTTP upload (#29)', select: { no: 29 } },
                    { text: 'Mark the upload (#29)', mark: [29] },
                    {
                        text: 'Which summary best fits the capture?',
                        quiz: {
                            q: 'Which summary best fits this capture?',
                            options: [
                                'A single failed TLS handshake',
                                'A host is spoofing the gateway, scanning ports and sending data to suspicious infrastructure',
                                'A healthy DNS server under normal load'
                            ],
                            answer: 1,
                            explain: 'The ARP reply, scan burst, TXT lookups, binary upload and SNI all point to an active intrusion. Each protocol supplied one piece of the same case.'
                        }
                    }
                ]
            }
        ]
    });

    CHAPTERS.push({
        id: 'ch8',
        number: 8,
        title: 'IPv6 explorer',
        tagline: 'No ARP, no broadcast: discovery, AAAA records and hop limits.',
        capture: 'ipv6',
        level: 'Advanced',
        badge: { id: 'ipv6-explorer', name: 'IPv6 Explorer', icon: '⬢' },
        missions: [
            {
                id: 'v6-neighbours',
                title: 'Where did ARP go?',
                xp: 190,
                brief: 'This capture has no ARP at all. IPv6 replaces it with Neighbor Discovery, and every packet is IPv6 from the first frame.',
                learn: 'IPv6 has no broadcast and no ARP. Hosts discover each other with ICMPv6 Neighbor Solicitation (type 135) and Neighbor Advertisement (type 136), sent to solicited-node multicast addresses such as ff02::1:ff00:1. The filter `ipv6` keeps every frame in this capture.',
                hints: [
                    'Type ipv6 in the display filter. All 15 packets are IPv6.',
                    'Neighbor Solicitation is #3 and the matching advertisement is #4.'
                ],
                tasks: [
                    { text: 'Show all IPv6 traffic (ipv6)', filter: { expr: ['ipv6'], matches: 15 } },
                    { text: 'Select the Neighbor Solicitation (#3)', select: { no: 3 } },
                    { text: 'Select the Neighbor Advertisement (#4)', select: { no: 4 } },
                    {
                        text: 'Which protocol replaces ARP in IPv6?',
                        quiz: {
                            q: 'Which mechanism replaces ARP in IPv6?',
                            options: ['ICMPv6 Neighbor Discovery', 'DHCPv4', 'RARP'],
                            answer: 0,
                            explain: 'Neighbor Solicitation and Advertisement messages perform address resolution for IPv6. ARP is an IPv4-only protocol.'
                        }
                    }
                ]
            },
            {
                id: 'v6-router',
                title: 'Finding the router',
                xp: 190,
                brief: 'Before a host can reach the internet it needs a default gateway. The first two packets show that conversation.',
                learn: 'A host sends a Router Solicitation (ICMPv6 type 133) to ff02::2, the all-routers multicast group. The router answers with a Router Advertisement (type 134) carrying its link-layer address and prefix information. Both are link-local and use a hop limit of 255 as a safety check.',
                hints: [
                    'Filter icmpv6.type == 133 for the solicitation and icmpv6.type == 134 for the advertisement.',
                    'Packet #2 is the Router Advertisement from fe80::1.'
                ],
                tasks: [
                    { text: 'Show the Router Solicitation: icmpv6.type == 133', filter: { expr: ['icmpv6.type == 133'], matches: 1 } },
                    { text: 'Show the Router Advertisement: icmpv6.type == 134', filter: { expr: ['icmpv6.type == 134'], matches: 1 } },
                    { text: 'Select the Router Advertisement (#2)', select: { no: 2 } },
                    {
                        text: 'Which multicast group receives router solicitations?',
                        quiz: {
                            q: 'Which address receives IPv6 Router Solicitations?',
                            options: ['ff02::2 (all routers)', 'ff02::1 (all nodes)', '255.255.255.255'],
                            answer: 0,
                            explain: 'Routers listen on ff02::2. The all-nodes group ff02::1 is used for advertisements and other one-to-many messages.'
                        }
                    }
                ]
            },
            {
                id: 'v6-aaaa',
                title: 'The AAAA answer',
                xp: 200,
                brief: 'A name lookup over IPv6 returns an IPv6 address. Find the query type that makes that possible.',
                learn: 'DNS A records map names to IPv4 addresses; AAAA records map names to IPv6 addresses. `dns.qry.type == 28` selects AAAA queries and answers. The response in #6 carries 2001:db8::80, the address used by the TLS session that follows.',
                hints: [
                    'Filter dns.qry.type == 28 to keep both the query and its answer.',
                    'Packet #5 is the AAAA query for ipv6.example.com.'
                ],
                tasks: [
                    { text: 'Show only AAAA lookups (dns.qry.type == 28)', filter: { expr: ['dns.qry.type == 28'], matches: 2 } },
                    { text: 'Select the AAAA query (#5)', select: { no: 5 } },
                    { text: 'Select the AAAA response (#6)', select: { no: 6 } },
                    {
                        text: 'Which record type returns an IPv6 address?',
                        quiz: {
                            q: 'Which DNS record type returns an IPv6 address?',
                            options: ['AAAA', 'A', 'MX'],
                            answer: 0,
                            explain: 'A returns IPv4, AAAA returns IPv6, and MX returns a mail exchanger. The query type value for AAAA is 28.'
                        }
                    }
                ]
            },
            {
                id: 'v6-tls',
                title: 'TLS over IPv6',
                xp: 210,
                brief: 'The HTTPS session works exactly as it does over IPv4, but the addresses and checksums are different. Prove it with one port filter.',
                learn: 'TCP and TLS behave the same above the network layer. `tcp.port == 443` keeps both directions of the HTTPS conversation, and `tls.handshake.type == 1` isolates the Client Hello. IPv6 checksums are calculated over a pseudo-header that includes the IPv6 addresses.',
                hints: [
                    'Filter tcp.port == 443 — six packets belong to the connection.',
                    'The Client Hello is #10. Filter tls.handshake.type == 1 to confirm.'
                ],
                tasks: [
                    { text: 'Show the HTTPS conversation: tcp.port == 443', filter: { expr: ['tcp.port == 443'], matches: 6 } },
                    { text: 'Show only TLS Client Hellos', filter: { expr: ['tls.handshake.type == 1'], matches: 1 } },
                    { text: 'Select the Client Hello (#10)', select: { no: 10 } },
                    {
                        text: 'What does the Client Hello reveal?',
                        quiz: {
                            q: 'What does packet #10 reveal before encryption starts?',
                            options: ['The requested server name (SNI)', 'The page contents', 'The user\'s password'],
                            answer: 0,
                            explain: 'The Client Hello is cleartext. Its SNI extension names ipv6.example.com even though everything after the handshake is encrypted.'
                        }
                    }
                ]
            },
            {
                id: 'v6-hop-limit',
                title: 'One hop left',
                xp: 220,
                brief: 'IPv6 has a Hop Limit where IPv4 had a TTL. One echo request will never reach its destination. Find out why.',
                learn: 'The IPv6 Hop Limit is decremented by every router. A value of 1 means the next router must discard the packet and return ICMPv6 Time Exceeded. This is the same idea as traceroute, and it is the IPv6 equivalent of a low TTL. `ipv6.hlim == 1` finds the doomed packet.',
                hints: [
                    'Filter ipv6.hlim == 1. Only packet #15 matches.',
                    'ICMPv6 traffic uses next header 58. Filter ipv6.nxt == 58 to see all seven control messages.'
                ],
                tasks: [
                    { text: 'Show packets with a hop limit of 1', filter: { expr: ['ipv6.hlim == 1'], matches: 1 } },
                    { text: 'Select the doomed echo request (#15)', select: { no: 15 } },
                    { text: 'Show all ICMPv6 messages: ipv6.nxt == 58', filter: { expr: ['ipv6.nxt == 58'], matches: 7 } },
                    {
                        text: 'What happens to a packet with Hop Limit 1 at a router?',
                        quiz: {
                            q: 'What happens when an IPv6 packet with Hop Limit 1 reaches a router?',
                            options: ['It is dropped and Time Exceeded is returned', 'It is delivered normally', 'It is converted to IPv4'],
                            answer: 0,
                            explain: 'The router decrements the hop limit to zero, discards the packet, and sends ICMPv6 Time Exceeded back to the source.'
                        }
                    }
                ]
            }
        ]
    });

    CHAPTERS.push({
        id: 'ch9',
        number: 9,
        title: 'Web forensics',
        tagline: 'Logins, redirects, cookies and downloads — read the HTTP story.',
        capture: 'web',
        level: 'Advanced',
        badge: { id: 'web-forensics', name: 'Web Forensicist', icon: '☵' },
        missions: [
            {
                id: 'web-login',
                title: 'The login POST',
                xp: 200,
                brief: 'A session starts with credentials sent in a POST body. Find the request and see what the client submitted.',
                learn: 'HTTP methods describe intent: GET retrieves, POST submits data. Login forms usually POST to a path such as /login with a Content-Type of application/x-www-form-urlencoded. The credentials are in the body, which is why HTTPS matters. `http.request.method == "POST"` isolates the request.',
                hints: [
                    'Filter http.request.method == "POST". Exactly one request matches.',
                    'Packet #6 is the POST /login. Expand the HTTP layer to read the body.'
                ],
                tasks: [
                    { text: 'Show only POST requests', filter: { expr: ['http.request.method == "POST"'], matches: 1 } },
                    { text: 'Show requests whose URI contains login', filter: { expr: ['http.request.uri contains login'], matches: 1 } },
                    { text: 'Select the login request (#6)', select: { no: 6 } },
                    {
                        text: 'Why is a login POST sensitive over plain HTTP?',
                        quiz: {
                            q: 'Why is the login in packet #6 sensitive when sent over HTTP?',
                            options: ['The username and password travel in cleartext', 'POST requests cannot be filtered', 'The port number is secret'],
                            answer: 0,
                            explain: 'Without TLS, anyone on the path can read the form body. HTTPS would encrypt the request after the handshake.'
                        }
                    }
                ]
            },
            {
                id: 'web-redirect',
                title: 'Follow the redirect',
                xp: 200,
                brief: 'The server does not return the account page directly. It answers with a redirect, and the client follows it.',
                learn: 'HTTP 3xx codes redirect the client. 302 Found is temporary, and the target is carried in the Location header. `http.response.code == 302` finds the redirect; `http.location contains account` proves where it points.',
                hints: [
                    'Filter http.response.code == 302. Packet #8 is the redirect.',
                    'The Location header reads /account and the next request (#10) follows it.'
                ],
                tasks: [
                    { text: 'Show the redirect response (http.response.code == 302)', filter: { expr: ['http.response.code == 302'], matches: 1 } },
                    { text: 'Show redirects pointing at account', filter: { expr: ['http.location contains account'], matches: 1 } },
                    { text: 'Select the 302 response (#8)', select: { no: 8 } },
                    {
                        text: 'What does the 302 response tell the browser?',
                        quiz: {
                            q: 'What does the 302 response in packet #8 tell the browser?',
                            options: ['Fetch /account next', 'The account page is missing', 'The connection was reset'],
                            answer: 0,
                            explain: 'The Location header names the next resource. Packet #10 is the browser following that instruction.'
                        }
                    }
                ]
            },
            {
                id: 'web-cookies',
                title: 'Cookie handoff',
                xp: 210,
                brief: 'The server hands out a session cookie, then the client presents it on the next request. Track the handoff.',
                learn: 'Set-Cookie creates or updates a cookie in the browser. Cookie sends it back on later requests. `http.set_cookie contains session` finds the response that issued it, while `http.cookie contains session` finds requests that carry it. A session cookie is a bearer token: anyone who captures it may be able to impersonate the user.',
                hints: [
                    'Filter http.cookie contains session — two requests carry a session cookie.',
                    'Packet #8 issues session=abc123 and packet #10 sends it back.'
                ],
                tasks: [
                    { text: 'Show requests carrying a session cookie', filter: { expr: ['http.cookie contains session'], matches: 2 } },
                    { text: 'Show the response that sets a session cookie', filter: { expr: ['http.set_cookie contains session'], matches: 1 } },
                    { text: 'Select the request that reuses the cookie (#10)', select: { no: 10 } },
                    {
                        text: 'Where did session=abc123 come from?',
                        quiz: {
                            q: 'How did the client obtain session=abc123?',
                            options: ['The 302 response set it with Set-Cookie', 'It was typed into the URL', 'DNS returned it'],
                            answer: 0,
                            explain: 'Packet #8 contains Set-Cookie: session=abc123. Packet #10 then sends that value back in its Cookie header.'
                        }
                    }
                ]
            },
            {
                id: 'web-tracking',
                title: 'The third-party pixel',
                xp: 220,
                brief: 'A page load quietly contacts a different domain. The Referer header explains why.',
                learn: 'Third-party requests are made to a host other than the page you are visiting. A tracking pixel is often a tiny GIF requested with context in the Referer header. `http.host == "metrics.example.org"` isolates the tracker, and `http.referer contains shop` shows which shop pages triggered it.',
                hints: [
                    'Filter http.host == "metrics.example.org". Packet #20 is the tracking request.',
                    'Filter http.referer contains shop to see both the account request and the tracker.'
                ],
                tasks: [
                    { text: 'Show the tracker host: http.host == "metrics.example.org"', filter: { expr: ['http.host == "metrics.example.org"'], matches: 1 } },
                    { text: 'Show requests referred by the shop', filter: { expr: ['http.referer contains shop'], matches: 2 } },
                    { text: 'Select the tracking request (#20)', select: { no: 20 } },
                    {
                        text: 'Why is this request third-party?',
                        quiz: {
                            q: 'Why is packet #20 considered third-party tracking?',
                            options: ['It goes to a different domain than the page and carries its URL in Referer', 'It uses port 80', 'It is a POST request'],
                            answer: 0,
                            explain: 'The Host is metrics.example.org while the Referer is shop.example.com, so a different company can observe which shop page the user visited.'
                        }
                    }
                ]
            },
            {
                id: 'web-download',
                title: 'The binary download',
                xp: 230,
                brief: 'One response is not a web page. It is an attachment, and the first bytes are suspicious. Find it without reading every frame.',
                learn: '`http.content_type contains octet-stream` finds generic binary downloads, and Content-Disposition names the saved file. The body of #32 begins with MZ, the DOS/PE executable signature. A 404 elsewhere in the capture is unrelated noise: always separate a missing page from a successful file transfer.',
                hints: [
                    'Filter http.content_type contains octet-stream. Packet #32 is the download.',
                    'The file begins with MZ. The 404 response is packet #35.'
                ],
                tasks: [
                    { text: 'Show the binary download (content type octet-stream)', filter: { expr: ['http.content_type contains octet-stream'], matches: 1 } },
                    { text: 'Select the download response (#32)', select: { no: 32 } },
                    { text: 'Show the unrelated 404 response', filter: { expr: ['http.response.code == 404'], matches: 1 } },
                    {
                        text: 'What do the first two bytes MZ suggest?',
                        quiz: {
                            q: 'What does the MZ signature at the start of the download suggest?',
                            options: ['A Windows executable', 'A compressed image', 'A DNS response'],
                            answer: 0,
                            explain: 'MZ is the DOS/PE executable header. Combined with Content-Disposition: attachment, this is a file worth quarantining and analysing.'
                        }
                    }
                ]
            },
            {
                id: 'web-case',
                title: 'Web case file',
                xp: 260,
                brief: 'Bring the whole browsing session together: requests, responses and the two packets that matter most.',
                learn: 'A web investigation separates requests from responses, then follows state: login, cookie, redirect, third-party call, download. Marking packets preserves evidence while you apply filters. `http.request` and `http.response` split the capture cleanly into six each.',
                hints: [
                    'Filter http.request, then http.response. Each should return six packets.',
                    'Mark the login POST (#6) and the binary download (#32) with Ctrl+M.'
                ],
                tasks: [
                    { text: 'Show all HTTP requests', filter: { expr: ['http.request'], matches: 6 } },
                    { text: 'Show all HTTP responses', filter: { expr: ['http.response'], matches: 6 } },
                    { text: 'Select the login POST (#6)', select: { no: 6 } },
                    { text: 'Mark the login POST (#6)', mark: [6] },
                    { text: 'Select the binary download (#32)', select: { no: 32 } },
                    { text: 'Mark the binary download (#32)', mark: [32] },
                    {
                        text: 'Which pair best summarises the risk?',
                        quiz: {
                            q: 'Which two packets best summarise the risk in this capture?',
                            options: ['The cleartext login POST and the executable download', 'The DNS query and the 404 response', 'The 304 response and the logo request'],
                            answer: 0,
                            explain: 'Credentials crossed the wire without TLS, and a binary executable was downloaded. Those are the two findings an analyst should escalate.'
                        }
                    }
                ]
            }
        ]
    });

    CHAPTERS.push({
        id: 'ch10',
        number: 10,
        title: 'Encrypted traffic',
        tagline: 'When the payload is dark, the handshake still tells the story.',
        capture: 'encrypted',
        level: 'Expert',
        badge: { id: 'tls-analyst', name: 'TLS Analyst', icon: '⌘' },
        missions: [
            {
                id: 'tls-hellos',
                title: 'Three hellos',
                xp: 230,
                brief: 'Three separate TLS sessions leave three Client Hellos. Find all of them without reading a single encrypted byte.',
                learn: 'A TLS handshake starts with a Client Hello (handshake type 1). Even in a capture full of application data, `tls.handshake.type == 1` isolates the moments where the client announced itself. Here packets #10, #20 and #30 are the three hellos.',
                hints: [
                    'Filter tls.handshake.type == 1. Three packets match.',
                    'Packet #10 is the first Client Hello, to telemetry.example.net.'
                ],
                tasks: [
                    { text: 'Show all TLS Client Hellos', filter: { expr: ['tls.handshake.type == 1'], matches: 3 } },
                    { text: 'Select the first Client Hello (#10)', select: { no: 10 } },
                    {
                        text: 'What starts a TLS handshake?',
                        quiz: {
                            q: 'Which handshake message starts a TLS session?',
                            options: ['Client Hello', 'Application Data', 'Alert'],
                            answer: 0,
                            explain: 'The client opens with a Client Hello listing versions, cipher suites and extensions such as SNI. The server answers with a Server Hello.'
                        }
                    }
                ]
            },
            {
                id: 'tls-server-flight',
                title: 'Server flight',
                xp: 240,
                brief: 'Each server answers with a hello and a certificate. Find the certificates without decrypting anything.',
                learn: 'Server Hello is handshake type 2 and Certificate is type 11. Certificates are usually public: they identify the server and its issuer even when application data is encrypted. `tls.handshake.type == 11` returns all three certificate messages in this capture.',
                hints: [
                    'Filter tls.handshake.type == 2 for Server Hellos and tls.handshake.type == 11 for certificates.',
                    'Packets #12, #22 and #32 are the three Certificate messages.'
                ],
                tasks: [
                    { text: 'Show all Server Hellos', filter: { expr: ['tls.handshake.type == 2'], matches: 3 } },
                    { text: 'Show all TLS certificates', filter: { expr: ['tls.handshake.type == 11'], matches: 3 } },
                    { text: 'Select the first certificate (#12)', select: { no: 12 } },
                    {
                        text: 'Which handshake message carries the certificate?',
                        quiz: {
                            q: 'Which TLS handshake message carries the server certificate?',
                            options: ['Type 11 (Certificate)', 'Type 1 (Client Hello)', 'Type 21 (Alert)'],
                            answer: 0,
                            explain: 'The Certificate message is handshake type 11. It is sent in the clear in TLS 1.2, so names and issuers remain visible.'
                        }
                    }
                ]
            },
            {
                id: 'tls-sni-audit',
                title: 'SNI audit',
                xp: 250,
                brief: 'One of the three destinations looks wrong. Read the requested hostnames and rank the risk.',
                learn: 'SNI is an extension of the Client Hello, sent before encryption. `tls.handshake.extensions_server_name` lets you inventory every hostname a client asked for. A domain such as updates.bad-cdn.example combines an update theme with an obviously suspicious label, and it does not match the DNS answers for the legitimate services.',
                hints: [
                    'Filter tls.handshake.extensions_server_name contains bad-cdn.',
                    'Packet #20 asks for updates.bad-cdn.example on port 8443.'
                ],
                tasks: [
                    { text: 'Show the legitimate telemetry SNI', filter: { expr: ['tls.handshake.extensions_server_name == "telemetry.example.net"'], matches: 1 } },
                    { text: 'Show the suspicious bad-cdn SNI', filter: { expr: ['tls.handshake.extensions_server_name contains bad-cdn'], matches: 1 } },
                    { text: 'Select the suspicious Client Hello (#20)', select: { no: 20 } },
                    {
                        text: 'Why is the bad-cdn hostname suspicious?',
                        quiz: {
                            q: 'Why is updates.bad-cdn.example suspicious in this capture?',
                            options: ['It imitates an update service on a domain that looks malicious', 'It uses a certificate', 'It sends a Server Hello'],
                            answer: 0,
                            explain: 'The name pairs a trusted-sounding "updates" label with "bad-cdn". That is a common masquerading pattern, and the traffic goes to a non-standard HTTPS port.'
                        }
                    }
                ]
            },
            {
                id: 'tls-alert-case',
                title: 'The handshake fails',
                xp: 250,
                brief: 'One session ends with an alert instead of application data. Find the exact reason code.',
                learn: 'TLS Alert is content type 21. Its Description field explains the failure: 40 is handshake_failure, 42 is bad_certificate, 70 is protocol_version. `tls.alert.description == 40` isolates this alert. Alerts are metadata, so they remain readable in an otherwise encrypted capture.',
                hints: [
                    'Filter tls.alert.description == 40. Packet #23 is the alert.',
                    'The same session uses TCP port 8443 — filter tcp.port == 8443 to see all ten of its packets.'
                ],
                tasks: [
                    { text: 'Show the handshake_failure alert', filter: { expr: ['tls.alert.description == 40'], matches: 1 } },
                    { text: 'Select the alert packet (#23)', select: { no: 23 } },
                    { text: 'Show the whole non-standard HTTPS session', filter: { expr: ['tcp.port == 8443'], matches: 10 } },
                    {
                        text: 'What does alert 40 mean?',
                        quiz: {
                            q: 'What does TLS alert description 40 mean?',
                            options: ['handshake_failure', 'bad_certificate', 'close_notify'],
                            answer: 0,
                            explain: 'Description 40 is handshake_failure: the peers could not agree on a usable handshake. The alert itself is cleartext even though the session never became usable.'
                        }
                    }
                ]
            },
            {
                id: 'tls-legacy',
                title: 'Legacy TLS',
                xp: 260,
                brief: 'The third session negotiates an ancient protocol version. Prove it from the record header alone.',
                learn: 'The TLS record header contains a 2-byte version. 0x0301 is TLS 1.0, 0x0303 is TLS 1.2 and 0x0304 is TLS 1.3. `tls.record.version == 0x0301` finds every record in the legacy session. Modern policy should reject TLS 1.0, so this is a finding even if the traffic is encrypted.',
                hints: [
                    'Filter tls.record.version == 0x0301. Packets #30–#32 match.',
                    'Look at the version field in packet #30: TLS 1.0.'
                ],
                tasks: [
                    { text: 'Show legacy TLS 1.0 records', filter: { expr: ['tls.record.version == 0x0301'], matches: 3 } },
                    { text: 'Select the legacy Client Hello (#30)', select: { no: 30 } },
                    {
                        text: 'Which version is 0x0301?',
                        quiz: {
                            q: 'Which TLS version is encoded as 0x0301?',
                            options: ['TLS 1.0', 'TLS 1.2', 'TLS 1.3'],
                            answer: 0,
                            explain: '0x0301 is TLS 1.0, 0x0303 is TLS 1.2 and 0x0304 is TLS 1.3. TLS 1.0 is deprecated and should be disabled.'
                        }
                    }
                ]
            },
            {
                id: 'tls-case',
                title: 'Encrypted case file',
                xp: 290,
                brief: 'Close the case: inventory the TLS sessions, preserve the suspicious evidence and summarise the findings.',
                learn: 'Encrypted does not mean invisible. Handshake types, SNI, certificates, versions and alerts form a metadata trail. `tls` keeps all twelve TLS records; marking the suspicious Client Hello and the failed alert preserves the key evidence across filters.',
                hints: [
                    'Filter tls. There are twelve TLS records in the capture.',
                    'Mark the suspicious Client Hello (#20) and the alert (#23) with Ctrl+M.'
                ],
                tasks: [
                    { text: 'Show every TLS record', filter: { expr: ['tls'], matches: 12 } },
                    { text: 'Select the suspicious Client Hello (#20)', select: { no: 20 } },
                    { text: 'Mark the suspicious Client Hello (#20)', mark: [20] },
                    { text: 'Select the failed alert (#23)', select: { no: 23 } },
                    { text: 'Mark the failed alert (#23)', mark: [23] },
                    {
                        text: 'Which summary best fits the capture?',
                        quiz: {
                            q: 'Which summary best fits this encrypted capture?',
                            options: [
                                'Three TLS sessions: one suspicious SNI, one failed handshake and one legacy version',
                                'A single healthy HTTPS session',
                                'Only DNS traffic'
                            ],
                            answer: 0,
                            explain: 'The metadata tells three stories: a bad-cdn hostname, a handshake_failure alert and a TLS 1.0 session. None required decrypting the payload.'
                        }
                    }
                ]
            }
        ]
    });

    CHAPTERS.push({
        id: 'ch11',
        number: 11,
        title: 'Malware traffic',
        tagline: 'From a failed DGA lookup to an executable download and a hidden beacon.',
        capture: 'malware',
        level: 'Expert',
        badge: { id: 'malware-analyst', name: 'Malware Analyst', icon: '☠' },
        missions: [
            {
                id: 'mal-dga',
                title: 'The DGA misfire',
                xp: 220,
                brief: 'The first lookup is a random-looking name that does not exist. That failure is itself a clue.',
                learn: 'Malware often generates pseudo-random domains (a domain generation algorithm, or DGA) to find its controller. Most guesses fail with NXDOMAIN (DNS RCODE 3). The one successful lookup that follows is the real infrastructure. `dns.flags.rcode == 3` isolates the failures.',
                hints: [
                    'Filter dns.flags.rcode == 3. Packet #2 is the only NXDOMAIN response.',
                    'The random name x7k2m9q4v1.example never resolves; update-checker.top does.'
                ],
                tasks: [
                    { text: 'Show the failed DGA lookup', filter: { expr: ['dns.flags.rcode == 3'], matches: 1 } },
                    { text: 'Select the NXDOMAIN response (#2)', select: { no: 2 } },
                    { text: 'Show both packets for the random name', filter: { expr: ['dns.qry.name == "x7k2m9q4v1.example"'], matches: 2 } },
                    {
                        text: 'Why does the DGA produce NXDOMAIN?',
                        quiz: {
                            q: 'Why does packet #2 return NXDOMAIN?',
                            options: ['The generated domain name does not exist', 'The DNS server is offline', 'The query used TCP'],
                            answer: 0,
                            explain: 'The algorithm guessed a name that is not registered. The malware keeps trying until one generated domain resolves to its controller.'
                        }
                    }
                ]
            },
            {
                id: 'mal-payload',
                title: 'The executable download',
                xp: 240,
                brief: 'One HTTP response is not a page. It is a Windows executable with a very recognisable first two bytes.',
                learn: 'A malicious download often hides behind an ordinary GET. `http.content_type contains octet-stream` finds generic binaries, and the body signature confirms the file type. MZ is the DOS/PE header used by Windows executables. The filename in Content-Disposition is attacker-chosen, so trust the bytes more than the name.',
                hints: [
                    'Filter http.request.uri contains payload. Packet #8 is the GET.',
                    'Packet #10 carries application/octet-stream and begins with MZ.'
                ],
                tasks: [
                    { text: 'Show the payload request', filter: { expr: ['http.request.uri contains payload'], matches: 1 } },
                    { text: 'Select the payload request (#8)', select: { no: 8 } },
                    { text: 'Show the binary response', filter: { expr: ['http.content_type contains octet-stream'], matches: 1 } },
                    { text: 'Select the executable download (#10)', select: { no: 10 } },
                    {
                        text: 'What does the MZ prefix prove?',
                        quiz: {
                            q: 'What does the MZ prefix at the start of packet #10 tell you?',
                            options: ['The body is a Windows executable', 'The body is an HTML page', 'The body is encrypted TLS data'],
                            answer: 0,
                            explain: 'MZ is the DOS/PE executable signature. The download is a program, not an image or document, despite any friendly filename.'
                        }
                    }
                ]
            },
            {
                id: 'mal-user-agent',
                title: 'The wrong browser',
                xp: 230,
                brief: 'Both HTTP requests claim to come from a scripted Windows component, not the user\'s browser. Find the common fingerprint.',
                learn: 'User-Agent strings identify the client software. `WinHttp.WinHttpRequest` is a Windows HTTP library often abused by malware, while a normal browser sends a Mozilla/Chrome/Firefox string. `http.user_agent contains WinHttp` links the download and the later gate POST to the same implant.',
                hints: [
                    'Filter http.user_agent contains WinHttp. Packets #8 and #32 match.',
                    'The download host is update-checker.top. Filter http.host == "update-checker.top".'
                ],
                tasks: [
                    { text: 'Show both WinHttp requests', filter: { expr: ['http.user_agent contains WinHttp'], matches: 2 } },
                    { text: 'Select the first WinHttp request (#8)', select: { no: 8 } },
                    { text: 'Show the download host', filter: { expr: ['http.host == "update-checker.top"'], matches: 1 } },
                    {
                        text: 'Why is the User-Agent suspicious here?',
                        quiz: {
                            q: 'Why is the WinHttp User-Agent suspicious in this capture?',
                            options: ['It is a scripted HTTP library, not the user\'s browser', 'It is too long to be valid', 'It always means the traffic is encrypted'],
                            answer: 0,
                            explain: 'A Windows service or library is making the request. That is normal for some software, but combined with a binary download and a gate POST it links the activity to an implant.'
                        }
                    }
                ]
            },
            {
                id: 'mal-beacon',
                title: 'The hidden beacon',
                xp: 250,
                brief: 'After the download, the host opens HTTPS to a name that has nothing to do with the download server. Read the SNI.',
                learn: 'TLS hides the payload but not the Client Hello. `tls.handshake.extensions_server_name` exposes the requested host, and the certificate is readable in TLS 1.2. A telemetry-sounding name on an unrelated address is a common C2 disguise. The beacon follows the download within seconds.',
                hints: [
                    'Filter tls.handshake.extensions_server_name contains sync-telemetry.',
                    'Packet #20 is the Client Hello; #21 and #22 are the server hello and certificate.'
                ],
                tasks: [
                    { text: 'Show the beacon SNI', filter: { expr: ['tls.handshake.extensions_server_name contains sync-telemetry'], matches: 1 } },
                    { text: 'Show the Client Hello', filter: { expr: ['tls.handshake.type == 1'], matches: 1 } },
                    { text: 'Select the beacon Client Hello (#20)', select: { no: 20 } },
                    {
                        text: 'What does the SNI connect the beacon to?',
                        quiz: {
                            q: 'What does the SNI in packet #20 reveal?',
                            options: ['The C2 hostname api.sync-telemetry.xyz', 'The downloaded file contents', 'The victim\'s password'],
                            answer: 0,
                            explain: 'SNI is sent in the clear. It ties the encrypted session to a named host even though the application data cannot be read.'
                        }
                    }
                ]
            },
            {
                id: 'mal-exfil',
                title: 'TXT exfiltration',
                xp: 240,
                brief: 'Four TXT lookups leave the host in a burst. DNS is the last protocol most networks block.',
                learn: 'DNS TXT records can carry arbitrary text. Malware encodes stolen data into a sequence of subdomains such as chunk1.exfil.evil-cdn.top, sending each chunk as a query. `dns.qry.type == 16` selects TXT, and `dns.qry.name contains exfil` ties the queries to the same campaign. The resolver sees the data even when HTTP is blocked.',
                hints: [
                    'Filter dns.qry.type == 16. Four queries and four responses match.',
                    'Packets #39–#46 are the exfiltration burst. Filter dns.qry.name contains exfil.'
                ],
                tasks: [
                    { text: 'Show all TXT lookups', filter: { expr: ['dns.qry.type == 16'], matches: 8 } },
                    { text: 'Show the exfiltration domains', filter: { expr: ['dns.qry.name contains exfil'], matches: 8 } },
                    { text: 'Select the first exfiltration query (#39)', select: { no: 39 } },
                    {
                        text: 'Why use DNS for exfiltration?',
                        quiz: {
                            q: 'Why is DNS a popular exfiltration channel?',
                            options: ['It is widely allowed through firewalls', 'It encrypts every query', 'It cannot be logged'],
                            answer: 0,
                            explain: 'DNS is essential, so it is often permitted outbound. Encoding data in TXT or subdomain labels can slip past controls that only inspect HTTP.'
                        }
                    }
                ]
            },
            {
                id: 'mal-gate',
                title: 'The gate POST',
                xp: 240,
                brief: 'The host sends a POST with an encoded body and a session cookie. Find the request and read its metadata.',
                learn: 'A gate or panel is a server-side script that receives implant check-ins. `http.request.method == "POST"` finds submissions, and `http.request.uri contains gate` finds this one. The Content-Type and Cookie headers are visible even if the body is encoded. POST bodies deserve scrutiny because they usually carry data out, not just request a page.',
                hints: [
                    'Filter http.request.method == "POST". Packet #32 is the only POST.',
                    'The URI is /gate.php and the Host is gate.sync-telemetry.xyz.'
                ],
                tasks: [
                    { text: 'Show all POST requests', filter: { expr: ['http.request.method == "POST"'], matches: 1 } },
                    { text: 'Show requests to a gate script', filter: { expr: ['http.request.uri contains gate'], matches: 1 } },
                    { text: 'Select the gate POST (#32)', select: { no: 32 } },
                    {
                        text: 'What is the POST carrying?',
                        quiz: {
                            q: 'What is the gate POST in packet #32 doing?',
                            options: ['Sending encoded victim data to the attacker', 'Downloading a stylesheet', 'Resolving a domain name'],
                            answer: 0,
                            explain: 'The body is form-encoded and the cookie identifies the implant. A gate endpoint is a classic check-in or exfiltration receiver.'
                        }
                    }
                ]
            },
            {
                id: 'mal-case',
                title: 'Malware case file',
                xp: 280,
                brief: 'Assemble the infection chain: a failed DGA, a binary download, a TLS beacon and a DNS exfiltration burst.',
                learn: 'A malware investigation links stages across protocols: initial resolution, delivery, execution-era beaconing, and exfiltration. Filters prove each stage; marks preserve the two packets that best tell the story. `ip.addr == 198.51.100.77` gathers every packet to the C2 address, including the ICMP keepalives.',
                hints: [
                    'Filter ip.addr == 198.51.100.77 — fourteen packets involve the C2 host.',
                    'Mark the downloaded executable (#10) and the C2 Client Hello (#20).'
                ],
                tasks: [
                    { text: 'Show every packet to or from the C2 host', filter: { expr: ['ip.addr == 198.51.100.77'], matches: 14 } },
                    { text: 'Open Statistics → Expert Information', dialog: ['Expert Information'] },
                    { text: 'Select the executable download (#10)', select: { no: 10 } },
                    { text: 'Mark the executable download (#10)', mark: [10] },
                    { text: 'Select the C2 Client Hello (#20)', select: { no: 20 } },
                    { text: 'Mark the C2 Client Hello (#20)', mark: [20] },
                    {
                        text: 'Which chain best summarises the capture?',
                        quiz: {
                            q: 'Which chain best summarises this malware capture?',
                            options: [
                                'DGA lookup, executable download, TLS beacon, gate POST, DNS exfiltration',
                                'A normal software update with no suspicious traffic',
                                'Only a DNS server failure'
                            ],
                            answer: 0,
                            explain: 'Each stage is visible in a different protocol. Together they describe a complete infection rather than a single failed request.'
                        }
                    }
                ]
            }
        ]
    });

    CHAPTERS.push({
        id: 'ch12',
        number: 12,
        title: 'Command & control',
        tagline: 'Four channels, one controller: HTTPS, HTTP, DNS and ICMP.',
        capture: 'c2',
        level: 'Expert',
        badge: { id: 'c2-hunter', name: 'C2 Hunter', icon: '⌖' },
        missions: [
            {
                id: 'c2-heartbeat',
                title: 'Heartbeat',
                xp: 250,
                brief: 'The same HTTPS destination is contacted twice with the same SNI. Repetition is the signature of a beacon.',
                learn: 'Implants check in on a schedule so they can receive new instructions. The interval may be fixed or jittered to evade detection. Here two separate TCP sessions carry Client Hellos for beacon.c2.example. `tls.handshake.extensions_server_name == "beacon.c2.example"` returns both, and `tcp.port == 443` shows every HTTPS packet.',
                hints: [
                    'Filter tls.handshake.extensions_server_name == "beacon.c2.example" — two hellos match.',
                    'The HTTPS conversations contain eighteen packets in total.'
                ],
                tasks: [
                    { text: 'Show both beacon SNI hellos', filter: { expr: ['tls.handshake.extensions_server_name == "beacon.c2.example"'], matches: 2 } },
                    { text: 'Select the first beacon hello (#6)', select: { no: 6 } },
                    { text: 'Show the HTTPS traffic', filter: { expr: ['tcp.port == 443'], matches: 18 } },
                    {
                        text: 'Why is a repeated beacon suspicious?',
                        quiz: {
                            q: 'Why does the repeated beacon to beacon.c2.example matter?',
                            options: ['Regular check-ins suggest automated command-and-control', 'It proves the website is popular', 'It means TLS is broken'],
                            answer: 0,
                            explain: 'A human browsing session is irregular. The same host checking in again with the same SNI at a machine-like interval is a beacon pattern.'
                        }
                    }
                ]
            },
            {
                id: 'c2-dns',
                title: 'DNS tunnel',
                xp: 260,
                brief: 'Four TXT queries carry numbered chunks. This is not ordinary name resolution; it is a data channel.',
                learn: 'A DNS tunnel encodes data in query names and retrieves commands in TXT answers. Numbered labels (chunk1, chunk2, …) and a shared parent domain reveal the sequence. `dns.qry.type == 16` isolates TXT traffic, and `dns.qry.name contains chunk` shows the tunnel payloads. Because the resolver forwards the queries, the tunnel works even when most outbound ports are blocked.',
                hints: [
                    'Filter dns.qry.type == 16. Eight packets match, four queries and four responses.',
                    'Packet #24 is the first chunk query.'
                ],
                tasks: [
                    { text: 'Show every TXT lookup', filter: { expr: ['dns.qry.type == 16'], matches: 8 } },
                    { text: 'Show the numbered tunnel chunks', filter: { expr: ['dns.qry.name contains chunk'], matches: 8 } },
                    { text: 'Select the first chunk query (#24)', select: { no: 24 } },
                    {
                        text: 'What makes this DNS traffic a tunnel?',
                        quiz: {
                            q: 'What makes these TXT queries a DNS tunnel?',
                            options: ['Numbered chunks encode data under one parent domain', 'They use UDP instead of TCP', 'They are sent to port 53'],
                            answer: 0,
                            explain: 'Ordinary DNS asks for a name once. Numbered subdomains carrying sequential data under a single parent are a covert channel.'
                        }
                    }
                ]
            },
            {
                id: 'c2-http',
                title: 'Fallback channel',
                xp: 250,
                brief: 'If HTTPS fails, the implant has a plain HTTP check-in. Find the fallback endpoint.',
                learn: 'Resilient malware ships with fallback channels. `http.host == "fallback.c2.example"` isolates the plaintext host, and `http.request.uri contains checkin` identifies the endpoint. The `curl/8.0` User-Agent is another scripted-client clue. A fallback over port 80 is easier to inspect, which is exactly why attackers prefer HTTPS when they can get it.',
                hints: [
                    'Filter http.host == "fallback.c2.example". Packet #17 is the request.',
                    'The URI is /api/v1/checkin and the reply is a small 200 OK.'
                ],
                tasks: [
                    { text: 'Show the fallback host', filter: { expr: ['http.host == "fallback.c2.example"'], matches: 1 } },
                    { text: 'Show the check-in endpoint', filter: { expr: ['http.request.uri contains checkin'], matches: 1 } },
                    { text: 'Select the fallback check-in (#17)', select: { no: 17 } },
                    {
                        text: 'Why does the implant keep an HTTP fallback?',
                        quiz: {
                            q: 'Why would an implant keep a plain HTTP fallback?',
                            options: ['To keep working if HTTPS is blocked or fails', 'To make the traffic harder to read', 'To avoid using DNS'],
                            answer: 0,
                            explain: 'Fallbacks add resilience. If TLS is filtered or the HTTPS controller is down, the implant can still check in over plain HTTP.'
                        }
                    }
                ]
            },
            {
                id: 'c2-icmp',
                title: 'ICMP keepalive',
                xp: 250,
                brief: 'Three echo requests leave for the HTTPS controller with a fixed identifier. Ping is being used as a channel.',
                learn: 'ICMP echo has no ports, so it can pass through policies that only allow web traffic. A fixed identifier and regular sequence numbers across repeated requests suggest automation rather than a user running ping. `icmp.type == 8` finds requests and `icmp.type == 0` finds replies. Repeated ICMP to the same rare destination is worth correlating with other channels.',
                hints: [
                    'Filter icmp.type == 8. Packets #32, #34 and #36 match.',
                    'The replies are icmp.type == 0 and share identifier 0x0c20.'
                ],
                tasks: [
                    { text: 'Show the ICMP echo requests', filter: { expr: ['icmp.type == 8'], matches: 3 } },
                    { text: 'Select the first ICMP beacon (#32)', select: { no: 32 } },
                    { text: 'Show the replies', filter: { expr: ['icmp.type == 0'], matches: 3 } },
                    {
                        text: 'Why is ICMP useful to an attacker?',
                        quiz: {
                            q: 'Why might malware use ICMP for a covert channel?',
                            options: ['It is often allowed and has no ports to block', 'It encrypts data automatically', 'It is faster than every other protocol'],
                            answer: 0,
                            explain: 'ICMP is commonly permitted for diagnostics. Without deep inspection, a steady stream of echo requests to one host can look like ordinary ping.'
                        }
                    }
                ]
            },
            {
                id: 'c2-jitter',
                title: 'Timing the beacons',
                xp: 270,
                brief: 'Use statistics to see the rhythm, then zoom in on the C2 address to connect all four channels.',
                learn: 'Beacon analysis is about time as much as content. IO Graph shows bursts at regular intervals, and Conversations reveals how much data each pair exchanged. Filtering `ip.addr == 198.51.100.77` gathers the HTTPS sessions and the ICMP keepalives, proving that different protocols share one controller.',
                hints: [
                    'Statistics → IO Graph and Statistics → Conversations are both under the Statistics menu.',
                    'Filter ip.addr == 198.51.100.77 — twenty-four packets involve that address.'
                ],
                tasks: [
                    { text: 'Open Statistics → IO Graph', dialog: ['IO Graph'] },
                    { text: 'Open Statistics → Conversations', dialog: ['Conversations'] },
                    { text: 'Show every packet to or from the C2 address', filter: { expr: ['ip.addr == 198.51.100.77'], matches: 24 } },
                    { text: 'Select the second beacon hello (#41)', select: { no: 41 } },
                    {
                        text: 'What does the shared destination prove?',
                        quiz: {
                            q: 'What does filtering on 198.51.100.77 reveal?',
                            options: ['HTTPS and ICMP channels share one controller', 'The host is only browsing the web', 'DNS is the only protocol in use'],
                            answer: 0,
                            explain: 'The same address receives both TLS beacons and ICMP keepalives. Correlating protocols by endpoint is a core C2 hunting technique.'
                        }
                    }
                ]
            },
            {
                id: 'c2-case',
                title: 'C2 case file',
                xp: 300,
                brief: 'Close the case: inventory the TLS records, preserve the two beacons and summarise the multi-channel infrastructure.',
                learn: 'A C2 investigation records the channels, their endpoints and the evidence that links them. `tls` returns the six TLS records across both beacon sessions. Marking the two Client Hellos preserves the SNI evidence while you inspect DNS, HTTP and ICMP. The final report should name every channel, not just the loudest one.',
                hints: [
                    'Filter tls — six TLS records match across the two sessions.',
                    'Mark the first and second beacon Client Hellos (#6 and #41) with Ctrl+M.'
                ],
                tasks: [
                    { text: 'Show every TLS record', filter: { expr: ['tls'], matches: 6 } },
                    { text: 'Select the first beacon hello (#6)', select: { no: 6 } },
                    { text: 'Mark the first beacon hello (#6)', mark: [6] },
                    { text: 'Select the second beacon hello (#41)', select: { no: 41 } },
                    { text: 'Mark the second beacon hello (#41)', mark: [41] },
                    {
                        text: 'Which summary best fits the capture?',
                        quiz: {
                            q: 'Which summary best fits this C2 capture?',
                            options: [
                                'An infected host uses HTTPS, HTTP, DNS and ICMP to reach command-and-control infrastructure',
                                'A user is browsing four unrelated websites',
                                'A DNS server is misconfigured'
                            ],
                            answer: 0,
                            explain: 'Four channels share suspicious infrastructure. The HTTPS beacons repeat, the HTTP check-in is a fallback, the DNS queries carry numbered chunks and ICMP provides a keepalive.'
                        }
                    }
                ]
            }
        ]
    });

    var EXTRA_MISSIONS = {
        ch1: [
            {
                id: 'teardown',
                title: 'Closing the conversation',
                xp: 110,
                brief: 'A TCP connection ends as deliberately as it begins. Find the FIN packets and the final ACK that retires the conversation.',
                learn: 'Either side can start a graceful close by setting the FIN flag. The peer answers with its own FIN, and the original sender confirms with a final ACK. A reset would abort the connection immediately instead.',
                hints: [
                    'Packets #14 and #15 both carry FIN. Packet #16 is the last ACK.',
                    'Filter tcp.flags.fin == 1 to see only the two teardown packets.'
                ],
                tasks: [
                    { text: 'Select the client FIN (#14)', select: { no: 14 } },
                    { text: 'Show only FIN packets (tcp.flags.fin == 1)', filter: { expr: ['tcp.flags.fin == 1'], matches: 2 } },
                    { text: 'Select the final ACK (#16)', select: { no: 16 } },
                    {
                        text: 'Which packet completes the TCP teardown?',
                        quiz: {
                            q: 'Which packet completes the TCP teardown?',
                            options: ['#14, the first FIN', '#15, the server FIN', '#16, the final ACK'],
                            answer: 2,
                            explain: 'The two FIN packets close each direction. Packet #16 is the ACK that confirms the server FIN, so the connection is fully closed.'
                        }
                    },
                    {
                        text: 'Count the FIN packets',
                        quiz: {
                            q: 'How many packets carry the FIN flag in this capture?',
                            options: ['1', '2', '3'],
                            answer: 1,
                            explain: 'Packet #14 and packet #15 set FIN, one from each side. Packet #16 is an ACK without FIN.'
                        }
                    }
                ]
            }
        ],
        ch2: [
            {
                id: 'filter-size',
                title: 'Size and direction',
                xp: 130,
                brief: 'Ports also encode direction. Filtering on the server source port shows only the bytes flowing back to the client.',
                learn: '`tcp.srcport` matches the sender port and `tcp.dstport` matches the receiver port. A client request uses a temporary source port and destination 80, while the response reverses those values. Combining a port with an HTTP field narrows the view to one role in the conversation.',
                hints: [
                    'The server answers from port 80, so tcp.srcport == 80 keeps its packets.',
                    'Packet #10 is the HTTP 200 response with the HTML body.'
                ],
                tasks: [
                    { text: 'Show traffic sent by the web server (tcp.srcport == 80)', filter: { expr: ['tcp.srcport == 80'], matches: 4 } },
                    { text: 'Show only HTTP GET requests', filter: { expr: ['http.request.method == "GET"'], matches: 1 } },
                    { text: 'Select the HTTP response (#10)', select: { no: 10 } },
                    {
                        text: 'Read the direction',
                        quiz: {
                            q: 'Which direction does tcp.srcport == 80 select?',
                            options: ['Packets sent by the web server', 'Packets sent by the client', 'Both directions equally'],
                            answer: 0,
                            explain: 'Source port 80 belongs to the server, so the filter keeps packets travelling from the server back to the client.'
                        }
                    },
                    {
                        text: 'Find the response',
                        quiz: {
                            q: 'Which packet carries the HTTP response body?',
                            options: ['#8, the GET request', '#10, the 200 OK response', '#13, the ICMP reply'],
                            answer: 1,
                            explain: 'Packet #10 is the HTTP/1.1 200 OK response. Packet #8 asks for the page and #13 is unrelated ICMP.'
                        }
                    }
                ]
            }
        ],
        ch3: [
            {
                id: 'cdn-side',
                title: 'The second conversation',
                xp: 150,
                brief: 'The capture contains two web servers. Separate the TLS session from the plain HTTP image download and identify who served what.',
                learn: 'A capture often mixes conversations. Grouping by port, host header or address keeps them apart. The shop session uses TLS on 443, while the CDN logo is fetched over plain HTTP on port 80, so the same client talks to two different services.',
                hints: [
                    'tcp.port == 80 keeps the CDN conversation in both directions.',
                    'The request Host header for the logo is cdn.example.net. Filter http.host == "cdn.example.net".'
                ],
                tasks: [
                    { text: 'Show the plain HTTP conversation (tcp.port == 80)', filter: { expr: ['tcp.port == 80'], matches: 9 } },
                    { text: 'Select the logo request (#22)', select: { no: 22 } },
                    { text: 'Show requests for the CDN host (http.host == "cdn.example.net")', filter: { expr: ['http.host == "cdn.example.net"'], matches: 1 } },
                    {
                        text: 'Name the image server',
                        quiz: {
                            q: 'Which host serves the logo image?',
                            options: ['shop.example.com', 'cdn.example.net', '10.0.0.53'],
                            answer: 1,
                            explain: 'The GET /logo.png request carries Host: cdn.example.net. The shop host used TLS and the resolver is 10.0.0.53.'
                        }
                    },
                    {
                        text: 'Identify the download port',
                        quiz: {
                            q: 'Which port carries the logo download?',
                            options: ['53', '80', '443'],
                            answer: 1,
                            explain: 'The logo is fetched over unencrypted HTTP on port 80. Port 443 carried the earlier TLS session and 53 is DNS.'
                        }
                    }
                ]
            }
        ],
        ch4: [
            {
                id: 'endpoint-counts',
                title: 'Count the endpoints',
                xp: 130,
                brief: 'Statistics turn a packet list into an inventory. Use Endpoints to find the resolver, then confirm its traffic with a filter.',
                learn: 'The Endpoints window totals packets and bytes for every address, so busy hosts stand out. The DNS resolver is the host answering port 53 traffic. A filter such as `ip.addr == 198.51.100.20` then isolates the CDN endpoint for closer inspection.',
                hints: [
                    'Open Statistics, then Endpoints, and sort by packets or bytes.',
                    'The resolver is 10.0.0.53. The CDN endpoint is 198.51.100.20.'
                ],
                tasks: [
                    { text: 'Open Statistics → Endpoints', dialog: ['Endpoints'] },
                    { text: 'Isolate the CDN endpoint (ip.addr == 198.51.100.20)', filter: { expr: ['ip.addr == 198.51.100.20'], matches: 9 } },
                    { text: 'Show all DNS traffic (udp.port == 53)', filter: { expr: ['udp.port == 53'], matches: 6 } },
                    {
                        text: 'Name the resolver',
                        quiz: {
                            q: 'Which address answers the DNS queries in this capture?',
                            options: ['10.0.0.5', '10.0.0.53', '203.0.113.50'],
                            answer: 1,
                            explain: 'The replies to port 53 come from 10.0.0.53. The client is 10.0.0.5 and 203.0.113.50 is the shop server.'
                        }
                    },
                    {
                        text: 'Count DNS packets',
                        quiz: {
                            q: 'How many DNS packets does this capture contain?',
                            options: ['4', '6', '9'],
                            answer: 1,
                            explain: 'There are three queries and three replies: A and AAAA for the shop, then A for the CDN. That makes six DNS packets.'
                        }
                    }
                ]
            }
        ],
        ch5: [
            {
                id: 'stall',
                title: 'The silent service',
                xp: 160,
                brief: 'A health check is sent and then nothing moves. Find the window update that explains the stall.',
                learn: 'A zero window means the receiver has no buffer space left, so the sender must pause. Seeing `[TCP ZeroWindow]` next to an ACK is stronger evidence than a missing response alone: the request arrived, but the server could not accept more data.',
                hints: [
                    'Packet #10 is GET /health and packet #11 is the zero-window ACK.',
                    'Filter tcp.window == 0 to confirm exactly one packet advertises no space.'
                ],
                tasks: [
                    { text: 'Show the health request (http.request.uri contains health)', filter: { expr: ['http.request.uri contains health'], matches: 1 } },
                    { text: 'Select the health request (#10)', select: { no: 10 } },
                    { text: 'Select the zero-window ACK (#11)', select: { no: 11 } },
                    {
                        text: 'Explain the stall',
                        quiz: {
                            q: 'Why does the transfer stall after the request?',
                            options: ['The server advertises a zero receive window', 'The server sends a reset', 'DNS returns NXDOMAIN'],
                            answer: 0,
                            explain: 'The server ACKs the request but advertises Win=0. It has no buffer space, so the client must wait instead of sending more data.'
                        }
                    },
                    {
                        text: 'Locate the zero window',
                        quiz: {
                            q: 'Which packet advertises a zero receive window?',
                            options: ['#9, the handshake ACK', '#10, the HTTP request', '#11, the server ACK'],
                            answer: 2,
                            explain: 'Packet #11 carries [TCP ZeroWindow] with Win=0. The earlier packets still advertise the normal window.'
                        }
                    }
                ]
            }
        ],
        ch6: [
            {
                id: 'fragment-set',
                title: 'Reassemble the fragments',
                xp: 200,
                brief: 'One UDP datagram is split across three IPv4 packets. Follow the Identification field to collect the whole set.',
                learn: 'IPv4 fragments of the same datagram share an Identification value. The first fragment has offset 0 and carries the transport header; later fragments have non-zero offsets and clear More Fragments on the last piece. Wireshark reassembles them only when every piece is present.',
                hints: [
                    'Packets #21, #22 and #23 share ip.id 0x1b58.',
                    'Filter ip.id == 0x1b58 to show the complete fragment set.'
                ],
                tasks: [
                    { text: 'Show the fragment set (ip.id == 0x1b58)', filter: { expr: ['ip.id == 0x1b58'], matches: 3 } },
                    { text: 'Select the first fragment (#21)', select: { no: 21 } },
                    { text: 'Select the last fragment (#23)', select: { no: 23 } },
                    {
                        text: 'Find the transport header',
                        quiz: {
                            q: 'Which fragment carries the UDP header?',
                            options: ['#21, the first fragment', '#22, the middle fragment', '#23, the last fragment'],
                            answer: 0,
                            explain: 'Only the first fragment starts at offset 0, so it holds the UDP header. Later fragments contain only the remaining payload bytes.'
                        }
                    },
                    {
                        text: 'Read the Identification field',
                        quiz: {
                            q: 'What does the IP Identification field group together?',
                            options: ['Fragments of one datagram', 'Separate TCP connections', 'DNS transactions'],
                            answer: 0,
                            explain: 'The sender copies one Identification value into every fragment of a datagram so the receiver can reassemble them correctly.'
                        }
                    }
                ]
            }
        ],
        ch7: [
            {
                id: 'scan-result',
                title: 'Reading the scan',
                xp: 210,
                brief: 'Nine ports are probed and every answer is a reset. Decide what that pattern proves before you escalate it.',
                learn: 'A SYN scan sends a SYN to each port. An open port answers SYN/ACK, a closed port answers RST/ACK, and a filtered port usually stays silent. Nine resets mean nine closed ports, but the sweep itself is still hostile reconnaissance.',
                hints: [
                    'The scanner is 10.0.0.66. Filter ip.src == 10.0.0.66 to see its SYNs.',
                    'Every probe is answered with RST/ACK, so no service accepted the connection.'
                ],
                tasks: [
                    { text: 'Show the scanner traffic (ip.src == 10.0.0.66)', filter: { expr: ['ip.src == 10.0.0.66'], matches: 9 } },
                    { text: 'Select the first probe (#4)', select: { no: 4 } },
                    { text: 'Show every reset (tcp.flags.rst == 1)', filter: { expr: ['tcp.flags.rst == 1'], matches: 9 } },
                    {
                        text: 'Count the probed ports',
                        quiz: {
                            q: 'How many destination ports did the scanner probe?',
                            options: ['8', '9', '10'],
                            answer: 1,
                            explain: 'The SYN packets target FTP, SSH, Telnet, SMTP, DNS, HTTPS, MySQL, RDP and 8080: nine ports in total.'
                        }
                    },
                    {
                        text: 'Interpret the resets',
                        quiz: {
                            q: 'What does a RST/ACK from the target mean for the scanned port?',
                            options: ['The port is closed', 'The port is open', 'The port is filtered'],
                            answer: 0,
                            explain: 'A closed TCP port replies with RST/ACK. An open port would complete SYN/ACK, and a filtered port would typically not answer at all.'
                        }
                    }
                ]
            }
        ],
        ch8: [
            {
                id: 'v6-echo',
                title: 'Echo over IPv6',
                xp: 200,
                brief: 'ICMPv6 has its own echo types, and the hop limit can stop a probe before it ever reaches the target.',
                learn: 'ICMPv6 type 128 is an echo request and type 129 is the reply. The IPv6 Hop Limit works like IPv4 TTL: every router decrements it, and a value of 1 means the next hop drops the packet. That makes a successful first echo and a failed second echo easy to explain.',
                hints: [
                    'Filter icmpv6.type == 128 to keep only the two echo requests.',
                    'Packet #15 arrives with hop limit 1, so it cannot cross another router.'
                ],
                tasks: [
                    { text: 'Show ICMPv6 echo requests (icmpv6.type == 128)', filter: { expr: ['icmpv6.type == 128'], matches: 2 } },
                    { text: 'Select the first echo request (#13)', select: { no: 13 } },
                    { text: 'Select the low-hop-limit request (#15)', select: { no: 15 } },
                    {
                        text: 'Name the echo request type',
                        quiz: {
                            q: 'Which ICMPv6 type is an echo request?',
                            options: ['128', '129', '135'],
                            answer: 0,
                            explain: 'Type 128 is the echo request and type 129 is the reply. Type 135 is a Neighbor Solicitation.'
                        }
                    },
                    {
                        text: 'Explain the failed echo',
                        quiz: {
                            q: 'Why does the second echo request fail?',
                            options: ['Its hop limit is 1 and expires', 'The destination has no IPv6 address', 'ICMPv6 cannot carry echo'],
                            answer: 0,
                            explain: 'A hop limit of 1 is exhausted at the next router. The first request had a normal limit and succeeded.'
                        }
                    }
                ]
            }
        ],
        ch9: [
            {
                id: 'web-status',
                title: 'Status codes tell the tale',
                xp: 210,
                brief: 'Two small responses explain a lot: a cached logo and a missing page. Read the codes instead of guessing from the payload.',
                learn: 'HTTP status codes describe the result, not the size of the body. 304 Not Modified tells the browser to reuse its cached copy, while 404 Not Found says the requested resource does not exist. Redirects use 3xx codes such as 302.',
                hints: [
                    'The logo request gets 304 and the /missing request gets 404.',
                    'Filter http.response.code == 304, then http.response.code == 404.'
                ],
                tasks: [
                    { text: 'Show the cached response (http.response.code == 304)', filter: { expr: ['http.response.code == 304'], matches: 1 } },
                    { text: 'Select the 304 response (#15)', select: { no: 15 } },
                    { text: 'Show the missing-page response (http.response.code == 404)', filter: { expr: ['http.response.code == 404'], matches: 1 } },
                    { text: 'Select the 404 response (#35)', select: { no: 35 } },
                    {
                        text: 'Interpret 304',
                        quiz: {
                            q: 'What does HTTP 304 tell the browser?',
                            options: ['The cached copy is still valid', 'The page does not exist', 'The request needs authentication'],
                            answer: 0,
                            explain: '304 Not Modified means the browser can reuse its cached copy. 404 means missing and 401 means authentication is required.'
                        }
                    },
                    {
                        text: 'Recognise a missing page',
                        quiz: {
                            q: 'Which response code reports a missing page?',
                            options: ['302', '304', '404'],
                            answer: 2,
                            explain: '404 Not Found is the missing-resource code. 302 is a redirect and 304 is a cache validation response.'
                        }
                    }
                ]
            }
        ],
        ch10: [
            {
                id: 'tls-sessions',
                title: 'Inventory the sessions',
                xp: 240,
                brief: 'Three TLS connections are opened and one is rejected. Count the sessions before you judge the encrypted payloads.',
                learn: 'Every TLS session begins with a TCP handshake, so counting SYNs without ACK gives the number of connection attempts. A session can then fail during the TLS handshake, as the alert on port 8443 shows. The port number identifies the service, not the success of the session.',
                hints: [
                    'There are three initial SYNs: ports 443, 8443 and 443 again.',
                    'The rejected session uses 8443. Filter tcp.dstport == 8443 to isolate its five packets.'
                ],
                tasks: [
                    { text: 'Show every new connection (SYN without ACK)', filter: { expr: ['tcp.flags.syn == 1 && tcp.flags.ack == 0'], matches: 3 } },
                    { text: 'Select the rejected session SYN (#17)', select: { no: 17 } },
                    { text: 'Show traffic to port 8443', filter: { expr: ['tcp.dstport == 8443'], matches: 5 } },
                    {
                        text: 'Count the sessions',
                        quiz: {
                            q: 'How many TLS sessions start in this capture?',
                            options: ['2', '3', '4'],
                            answer: 1,
                            explain: 'Three SYNs open three connections: telemetry on 443, the rejected updates session on 8443, and the CDN on 443.'
                        }
                    },
                    {
                        text: 'Find the failed service',
                        quiz: {
                            q: 'Which destination port carries the rejected session?',
                            options: ['80', '443', '8443'],
                            answer: 2,
                            explain: 'The handshake failure appears in the conversation to port 8443. The other two sessions use 443.'
                        }
                    }
                ]
            }
        ],
        ch11: [
            {
                id: 'infra',
                title: 'Map the infrastructure',
                xp: 250,
                brief: 'The implant talks to several servers. Separate the payload host, the TLS controller and the gate so the infection chain is clear.',
                learn: 'Malware often splits delivery and control across different hosts. The payload is fetched from one server, the beacon uses another, and a gate script on a third host confirms the victim. Matching hostnames to IP addresses turns a list of packets into an infrastructure map.',
                hints: [
                    'The gate POST goes to gate.sync-telemetry.xyz at 198.51.100.66.',
                    'The executable came from update-checker.top at 203.0.113.120.'
                ],
                tasks: [
                    { text: 'Show the gate conversation (ip.addr == 198.51.100.66)', filter: { expr: ['ip.addr == 198.51.100.66'], matches: 10 } },
                    { text: 'Select the gate POST (#32)', select: { no: 32 } },
                    { text: 'Show the gate DNS lookup (dns.qry.name == "gate.sync-telemetry.xyz")', filter: { expr: ['dns.qry.name == "gate.sync-telemetry.xyz"'], matches: 2 } },
                    {
                        text: 'Name the gate host',
                        quiz: {
                            q: 'Which hostname does the gate POST target?',
                            options: ['gate.sync-telemetry.xyz', 'update-checker.top', 'api.sync-telemetry.xyz'],
                            answer: 0,
                            explain: 'The Host header and the DNS lookup both name gate.sync-telemetry.xyz. The other names belong to the payload and beacon stages.'
                        }
                    },
                    {
                        text: 'Name the payload server',
                        quiz: {
                            q: 'Which server delivers the executable?',
                            options: ['203.0.113.120', '198.51.100.66', '198.51.100.77'],
                            answer: 0,
                            explain: 'The stage2.exe download comes from update-checker.top, which resolves to 203.0.113.120. The other addresses host the gate and the beacon.'
                        }
                    }
                ]
            }
        ],
        ch12: [
            {
                id: 'channels',
                title: 'Four channels, one host',
                xp: 260,
                brief: 'The implant spreads its check-ins across HTTPS, HTTP, DNS and ICMP. Inventory every channel before you block just one.',
                learn: 'A resilient implant keeps fallback channels. The HTTPS beacons blend with normal traffic, the HTTP check-in looks like an API call, DNS TXT queries carry chunks, and ICMP echo requests provide a portless keepalive. A single-port filter sees only part of the picture.',
                hints: [
                    'The DNS channel has A lookups for the beacon and fallback hosts plus eight TXT packets.',
                    'ICMP echo requests use type 8. There are three of them in this capture.'
                ],
                tasks: [
                    { text: 'Show every lookup for c2.example (dns.qry.name contains c2.example)', filter: { expr: ['dns.qry.name contains c2.example'], matches: 12 } },
                    { text: 'Select the first TXT chunk (#24)', select: { no: 24 } },
                    { text: 'Show ICMP echo requests (icmp.type == 8)', filter: { expr: ['icmp.type == 8'], matches: 3 } },
                    { text: 'Select the first ICMP keepalive (#32)', select: { no: 32 } },
                    {
                        text: 'Find the portless channel',
                        quiz: {
                            q: 'Which channel uses no TCP or UDP port?',
                            options: ['DNS', 'HTTP', 'ICMP'],
                            answer: 2,
                            explain: 'ICMP has no port numbers, which is why port-based firewall rules may not block it. DNS uses 53, HTTP uses 80 and HTTPS uses 443.'
                        }
                    },
                    {
                        text: 'Read the DNS channel',
                        quiz: {
                            q: 'Which DNS record type carries the tunnel chunks?',
                            options: ['A', 'TXT', 'AAAA'],
                            answer: 1,
                            explain: 'The chunk1 to chunk4 queries are TXT records. A records map names to IPv4 addresses and AAAA records map to IPv6.'
                        }
                    }
                ]
            }
        ]
    };

    CHAPTERS.forEach(function (chapter) {
        var extra = EXTRA_MISSIONS[chapter.id];
        if (!extra || !chapter.missions.length) return;
        chapter.missions.splice.apply(chapter.missions, [chapter.missions.length - 1, 0].concat(extra));
    });

    var EXTRA_QUIZZES = {
        'first-packet': {
            text: 'Which pane shows the raw bytes on the wire?',
            quiz: {
                q: 'Which pane shows the raw hex and ASCII bytes?',
                options: ['Packet list', 'Packet details', 'Packet bytes'],
                answer: 2,
                explain: 'The bottom pane is the packet bytes view: raw hex on the left and ASCII on the right.'
            }
        },
        'read-columns': {
            text: 'Read the Info column',
            quiz: {
                q: 'Which column gives the one-line summary of a frame?',
                options: ['No.', 'Length', 'Info'],
                answer: 2,
                explain: 'Info is Wireshark\'s short human-readable summary of what the frame is doing.'
            }
        },
        'one-story': {
            text: 'Name the resolver',
            quiz: {
                q: 'Which protocol resolves a name to an IP address before TCP connects?',
                options: ['ARP', 'DNS', 'HTTP'],
                answer: 1,
                explain: 'DNS turns the hostname into an address; ARP only maps an IP to a local MAC address.'
            }
        },
        'ping-pong': {
            text: 'Match the echo pair',
            quiz: {
                q: 'Which fields pair an ICMP echo request with its reply?',
                options: ['Identifier and Sequence Number', 'Source and destination ports', 'The checksum alone'],
                answer: 0,
                explain: 'ICMP has no ports. Wireshark uses the Identifier and Sequence Number to match a reply to its request.'
            }
        },
        'filter-protocol': {
            text: 'Ask for DNS only',
            quiz: {
                q: 'Which filter shows only DNS traffic?',
                options: ['arp', 'dns', 'http'],
                answer: 1,
                explain: 'A bare protocol name is a display filter. dns keeps only packets that contain DNS.'
            }
        },
        'filter-address': {
            text: 'Match either direction',
            quiz: {
                q: 'Which filter matches traffic in either direction for one host?',
                options: ['ip.addr == 203.0.113.10', 'ip.src == 203.0.113.10', 'tcp.port == 80'],
                answer: 0,
                explain: 'ip.addr matches either endpoint. ip.src is directional and only matches packets sent by that host.'
            }
        },
        'filter-logic': {
            text: 'Choose the OR operator',
            quiz: {
                q: 'Which operator means either condition can be true?',
                options: ['&&', '||', '!'],
                answer: 1,
                explain: '|| is logical OR: at least one side must be true. && requires both sides and ! inverts.'
            }
        },
        'filter-challenge': {
            text: 'Find DNS responses',
            quiz: {
                q: 'Which filter finds DNS responses?',
                options: ['dns.flags.response == 1', 'dns.flags.query == 1', 'dns.qry.type == 1'],
                answer: 0,
                explain: 'dns.flags.response is 1 on a response and 0 on a query. dns.qry.type == 1 would match A-record queries.'
            }
        },
        'port-story': {
            text: 'Spot the ephemeral port',
            quiz: {
                q: 'Which port is the usual start of the client ephemeral range?',
                options: ['53', '80', '49152'],
                answer: 2,
                explain: 'Clients usually pick an ephemeral source port from 49152 and above, while servers listen on well-known ports such as 53 and 80.'
            }
        },
        'dns-detail': {
            text: 'Recall the alias record',
            quiz: {
                q: 'Which DNS record type returns an alias?',
                options: ['A', 'CNAME', 'MX'],
                answer: 1,
                explain: 'CNAME maps one name to another. A returns an IPv4 address and MX names a mail server.'
            }
        },
        'tcp-handshake': {
            text: 'Finish the handshake',
            quiz: {
                q: 'What does the final ACK of the three-way handshake do?',
                options: ['Acknowledges the server\'s SYN/ACK', 'Reopens the connection', 'Closes the connection'],
                answer: 0,
                explain: 'The client sends ACK after receiving SYN/ACK, which completes the handshake and opens the connection.'
            }
        },
        'tls-sni': {
            text: 'Why SNI stays visible',
            quiz: {
                q: 'Why can you still read the requested hostname in TLS?',
                options: ['SNI is sent in the Client Hello before encryption', 'TLS encrypts only certificates', 'The hostname is in the TCP header'],
                answer: 0,
                explain: 'The Client Hello, including the SNI extension, is sent in the clear before the encrypted session begins.'
            }
        },
        'follow-stream': {
            text: 'Find Follow Stream',
            quiz: {
                q: 'Which action reassembles a TCP conversation?',
                options: ['Right-click → Follow → TCP Stream', 'Statistics → Conversations', 'View → Coloring Rules'],
                answer: 0,
                explain: 'Follow TCP Stream rebuilds the application payload in both directions from the selected packet.'
            }
        },
        'hierarchy': {
            text: 'Locate the menu entry',
            quiz: {
                q: 'Which menu contains Protocol Hierarchy?',
                options: ['Statistics', 'View', 'Edit'],
                answer: 0,
                explain: 'Protocol Hierarchy lives under the Statistics menu, alongside Conversations, Endpoints and IO Graph.'
            }
        },
        'conversations': {
            text: 'Group by pair',
            quiz: {
                q: 'Which view groups packets by address and port pair?',
                options: ['Protocol Hierarchy', 'Conversations', 'IO Graph'],
                answer: 1,
                explain: 'Conversations reports duration, packets and bytes for each address/port pair.'
            }
        },
        'io-graph': {
            text: 'Choose a fine interval',
            quiz: {
                q: 'Which interval makes individual exchanges visible in a short capture?',
                options: ['0.1 s', '10 s', '1 min'],
                answer: 0,
                explain: 'A short interval such as 0.1 s separates each exchange. Long intervals merge everything into one block.'
            }
        },
        'make-it-yours': {
            text: 'Mark a packet',
            quiz: {
                q: 'Which shortcut marks a packet?',
                options: ['Ctrl+M', 'Ctrl+F', 'Ctrl+K'],
                answer: 0,
                explain: 'Ctrl+M marks the selected packet. Marks survive filter changes, which makes them useful evidence markers.'
            }
        },
        'nxdomain': {
            text: 'Filter the failure',
            quiz: {
                q: 'Which filter finds NXDOMAIN responses?',
                options: ['dns.flags.rcode == 3', 'dns.flags.rcode == 0', 'dns.qry.type == 3'],
                answer: 0,
                explain: 'RCODE 3 is NXDOMAIN. RCODE 0 is success, and dns.qry.type is the record type, not the response code.'
            }
        },
        'connection-refused': {
            text: 'Name the reset flag',
            quiz: {
                q: 'Which TCP flag indicates a reset?',
                options: ['SYN', 'RST', 'FIN'],
                answer: 1,
                explain: 'RST tears the connection down or refuses it. SYN opens a connection and FIN closes one gracefully.'
            }
        },
        'zero-window': {
            text: 'Filter the stall',
            quiz: {
                q: 'Which filter finds zero-window packets?',
                options: ['tcp.window == 0', 'tcp.len == 0', 'tcp.flags.syn == 1'],
                answer: 0,
                explain: 'tcp.window == 0 finds the advertised zero receive window. tcp.len == 0 also matches ordinary ACKs.'
            }
        },
        'port-unreachable': {
            text: 'Identify the ICMP type',
            quiz: {
                q: 'Which ICMP type carries destination unreachable?',
                options: ['0', '3', '8'],
                answer: 1,
                explain: 'ICMP type 3 is destination unreachable. Type 0 is echo reply and type 8 is echo request.'
            }
        },
        'tls-alert': {
            text: 'Read the severity',
            quiz: {
                q: 'Which TLS alert severity value means fatal?',
                options: ['1', '2', '3'],
                answer: 1,
                explain: 'TLS alert severity 1 is a warning and 2 is fatal. The fatal alert closes the session.'
            }
        },
        'case-file': {
            text: 'Aggregate the warnings',
            quiz: {
                q: 'Which statistics view aggregates warnings and errors?',
                options: ['Protocol Hierarchy', 'Expert Information', 'Endpoints'],
                answer: 1,
                explain: 'Expert Information collects resets, zero windows, unreachable errors and other expert warnings in one list.'
            }
        },
        'retransmission': {
            text: 'Find both copies',
            quiz: {
                q: 'Which filter finds both copies of the repeated segment?',
                options: ['tcp.seq == 3099', 'tcp.ack == 3099', 'tcp.len == 0'],
                answer: 0,
                explain: 'A retransmission repeats the same sequence number and payload, so tcp.seq == 3099 returns both copies.'
            }
        },
        'dup-acks': {
            text: 'Count the trigger',
            quiz: {
                q: 'How many duplicate ACKs usually trigger fast retransmit?',
                options: ['1', '3', '10'],
                answer: 1,
                explain: 'Three duplicate ACKs are the classic fast-retransmit trigger, telling the sender a segment is missing.'
            }
        },
        'fragments': {
            text: 'Skip the first piece',
            quiz: {
                q: 'Which filter shows fragments after the first?',
                options: ['ip.frag_offset > 0', 'ip.frag_offset == 0', 'ip.flags.mf == 1'],
                answer: 0,
                explain: 'Only the first fragment has offset 0. Later fragments carry a non-zero offset.'
            }
        },
        'slow-transfer': {
            text: 'Watch the stall',
            quiz: {
                q: 'Which view shows a stall over time?',
                options: ['IO Graph', 'Protocol Hierarchy', 'Endpoints'],
                answer: 0,
                explain: 'IO Graph plots traffic over time, so a pause in the transfer appears as a gap in the series.'
            }
        },
        'arp-spoof': {
            text: 'Recall the mapping protocol',
            quiz: {
                q: 'Which protocol maps an IP address to a MAC address?',
                options: ['ARP', 'DNS', 'ICMP'],
                answer: 0,
                explain: 'ARP resolves a local IPv4 address to a MAC address. That is why a forged ARP reply can redirect traffic.'
            }
        },
        'port-scan': {
            text: 'Closed-port behaviour',
            quiz: {
                q: 'What do closed ports return to a SYN?',
                options: ['RST/ACK', 'SYN/ACK', 'ICMP echo'],
                answer: 0,
                explain: 'A closed port answers a SYN with RST/ACK. A SYN/ACK would mean the port is open.'
            }
        },
        'dns-tunnel': {
            text: 'Name the text record',
            quiz: {
                q: 'Which DNS record type can carry arbitrary text?',
                options: ['A', 'TXT', 'MX'],
                answer: 1,
                explain: 'TXT records hold free-form text, which makes them useful for encoding commands or stolen data.'
            }
        },
        'malicious-upload': {
            text: 'Pick the upload method',
            quiz: {
                q: 'Which HTTP method submits a file?',
                options: ['GET', 'POST', 'HEAD'],
                answer: 1,
                explain: 'POST carries a request body, so uploads and form submissions normally use it. GET retrieves and HEAD asks for headers only.'
            }
        },
        'c2-sni': {
            text: 'Filter the SNI',
            quiz: {
                q: 'Which filter isolates a specific TLS SNI?',
                options: ['tls.handshake.extensions_server_name == "..."', 'tls.handshake.type == 1', 'tcp.port == 443'],
                answer: 0,
                explain: 'The SNI extension field lets you match an exact hostname. tls.handshake.type == 1 returns every Client Hello.'
            }
        },
        'threat-case': {
            text: 'Open Expert Information',
            quiz: {
                q: 'Which menu opens Expert Information?',
                options: ['Statistics', 'View', 'Edit'],
                answer: 0,
                explain: 'Expert Information is under Statistics, next to Protocol Hierarchy and Conversations.'
            }
        },
        'v6-neighbours': {
            text: 'Name the solicitation type',
            quiz: {
                q: 'Which ICMPv6 type is Neighbor Solicitation?',
                options: ['133', '135', '136'],
                answer: 1,
                explain: 'Type 135 is Neighbor Solicitation and type 136 is Neighbor Advertisement. Type 133 is Router Solicitation.'
            }
        },
        'v6-router': {
            text: 'Name the advertisement type',
            quiz: {
                q: 'Which ICMPv6 type is Router Advertisement?',
                options: ['133', '134', '135'],
                answer: 1,
                explain: 'Type 134 is Router Advertisement. Type 133 is Router Solicitation and 135 is Neighbor Solicitation.'
            }
        },
        'v6-aaaa': {
            text: 'Read the answer address',
            quiz: {
                q: 'Which address does the AAAA response return?',
                options: ['198.51.100.20', '2001:db8::80', 'ff02::2'],
                answer: 1,
                explain: 'The AAAA answer carries the IPv6 address 2001:db8::80, which the following TLS session uses.'
            }
        },
        'v6-tls': {
            text: 'Find the hop counter',
            quiz: {
                q: 'Which IPv6 field limits how many routers a packet can cross?',
                options: ['Hop Limit', 'Traffic Class', 'Flow Label'],
                answer: 0,
                explain: 'Hop Limit is decremented by every router, just like IPv4 TTL. Traffic Class and Flow Label do not limit hops.'
            }
        },
        'v6-hop-limit': {
            text: 'Name the error',
            quiz: {
                q: 'Which ICMPv6 error is returned when the Hop Limit reaches zero?',
                options: ['Destination Unreachable', 'Time Exceeded', 'Packet Too Big'],
                answer: 1,
                explain: 'A router discards the packet and returns ICMPv6 Time Exceeded when the Hop Limit reaches zero.'
            }
        },
        'web-login': {
            text: 'Pick the read method',
            quiz: {
                q: 'Which HTTP method retrieves a page?',
                options: ['GET', 'POST', 'PUT'],
                answer: 0,
                explain: 'GET retrieves a resource. POST submits data, and PUT replaces a resource.'
            }
        },
        'web-redirect': {
            text: 'Find the redirect target',
            quiz: {
                q: 'Which header carries a redirect target?',
                options: ['Location', 'Referer', 'Host'],
                answer: 0,
                explain: 'The Location header tells the browser where to go next after a 3xx response.'
            }
        },
        'web-cookies': {
            text: 'Find the cookie setter',
            quiz: {
                q: 'Which response header asks the browser to store a cookie?',
                options: ['Set-Cookie', 'Cookie', 'Referer'],
                answer: 0,
                explain: 'Set-Cookie creates or updates a cookie. Cookie is sent by the client on later requests.'
            }
        },
        'web-tracking': {
            text: 'Find the source page',
            quiz: {
                q: 'Which header tells a tracker where the user came from?',
                options: ['Referer', 'Host', 'Cookie'],
                answer: 0,
                explain: 'Referer carries the URL of the page that made the request, which leaks browsing context to the tracker.'
            }
        },
        'web-download': {
            text: 'Filter the binary',
            quiz: {
                q: 'Which filter finds generic binary downloads?',
                options: ['http.content_type contains octet-stream', 'http.request.method == "GET"', 'http.response.code == 200'],
                answer: 0,
                explain: 'application/octet-stream is the generic binary content type used by many file downloads.'
            }
        },
        'web-case': {
            text: 'Split requests from responses',
            quiz: {
                q: 'Which filter shows only HTTP requests?',
                options: ['http.request', 'http.response', 'http.host'],
                answer: 0,
                explain: 'http.request matches request messages; http.response matches replies. Together they split the HTTP capture in two.'
            }
        },
        'tls-hellos': {
            text: 'Identify Server Hello',
            quiz: {
                q: 'Which handshake type is Server Hello?',
                options: ['1', '2', '11'],
                answer: 1,
                explain: 'Type 1 is Client Hello, type 2 is Server Hello and type 11 is Certificate.'
            }
        },
        'tls-server-flight': {
            text: 'What certificates prove',
            quiz: {
                q: 'What do certificates identify even when application data is encrypted?',
                options: ['The server and its issuer', 'The user\'s password', 'The HTTP body'],
                answer: 0,
                explain: 'The certificate chain names the server and its issuer. That metadata stays readable in TLS 1.2 captures.'
            }
        },
        'tls-sni-audit': {
            text: 'Name the SNI field',
            quiz: {
                q: 'Which field holds the requested hostname?',
                options: ['tls.handshake.extensions_server_name', 'tls.alert.description', 'tls.record.version'],
                answer: 0,
                explain: 'tls.handshake.extensions_server_name exposes the SNI value from the Client Hello.'
            }
        },
        'tls-alert-case': {
            text: 'Find the alert content type',
            quiz: {
                q: 'Which TLS content type is an alert?',
                options: ['21', '22', '23'],
                answer: 0,
                explain: 'Content type 21 is Alert, 22 is Handshake and 23 is Application Data.'
            }
        },
        'tls-legacy': {
            text: 'Identify TLS 1.2',
            quiz: {
                q: 'Which TLS record version is TLS 1.2?',
                options: ['0x0301', '0x0303', '0x0304'],
                answer: 1,
                explain: '0x0301 is TLS 1.0, 0x0303 is TLS 1.2 and 0x0304 is TLS 1.3.'
            }
        },
        'tls-case': {
            text: 'Show every TLS record',
            quiz: {
                q: 'Which filter returns every TLS record?',
                options: ['tls', 'tcp', 'http'],
                answer: 0,
                explain: 'The bare tls filter keeps every TLS record regardless of handshake type or direction.'
            }
        },
        'mal-dga': {
            text: 'Name the NXDOMAIN code',
            quiz: {
                q: 'Which DNS response code means the name does not exist?',
                options: ['0', '3', '5'],
                answer: 1,
                explain: 'RCODE 3 is NXDOMAIN. RCODE 0 is success and 5 is refused.'
            }
        },
        'mal-payload': {
            text: 'Find the saved filename',
            quiz: {
                q: 'Which HTTP header names the file being saved?',
                options: ['Content-Disposition', 'Content-Type', 'User-Agent'],
                answer: 0,
                explain: 'Content-Disposition carries the suggested filename. Content-Type describes the body, not its name.'
            }
        },
        'mal-user-agent': {
            text: 'Name the client header',
            quiz: {
                q: 'Which HTTP header identifies the client software?',
                options: ['User-Agent', 'Host', 'Cookie'],
                answer: 0,
                explain: 'User-Agent names the client library or browser. WinHttp in this capture points to a scripted Windows client.'
            }
        },
        'mal-beacon': {
            text: 'Where SNI travels',
            quiz: {
                q: 'Which TLS message carries the SNI extension?',
                options: ['Client Hello', 'Server Hello', 'Certificate'],
                answer: 0,
                explain: 'The client sends the SNI extension inside its Client Hello, before encryption starts.'
            }
        },
        'mal-exfil': {
            text: 'Name the exfil record',
            quiz: {
                q: 'Which DNS query type carried the exfiltration chunks?',
                options: ['A', 'TXT', 'MX'],
                answer: 1,
                explain: 'The chunks leave as TXT queries. TXT records can hold arbitrary text, which suits encoded data.'
            }
        },
        'mal-gate': {
            text: 'Filter the submission',
            quiz: {
                q: 'Which filter finds POST requests?',
                options: ['http.request.method == "POST"', 'http.response.code == 200', 'http.request.uri contains gate'],
                answer: 0,
                explain: 'http.request.method == "POST" matches every submission. The URI filter would only match this gate endpoint.'
            }
        },
        'mal-case': {
            text: 'Identify the C2 address',
            quiz: {
                q: 'Which address is the C2 host in this capture?',
                options: ['203.0.113.120', '198.51.100.77', '10.0.0.53'],
                answer: 1,
                explain: '198.51.100.77 receives the TLS beacon and the ICMP keepalives. 203.0.113.120 served the payload.'
            }
        },
        'c2-heartbeat': {
            text: 'Filter the beacon name',
            quiz: {
                q: 'Which filter shows both beacon Client Hellos?',
                options: ['tls.handshake.extensions_server_name == "beacon.c2.example"', 'tcp.port == 80', 'dns.qry.type == 16'],
                answer: 0,
                explain: 'Matching the SNI returns both Client Hellos for beacon.c2.example, one from each session.'
            }
        },
        'c2-dns': {
            text: 'Filter TXT lookups',
            quiz: {
                q: 'Which filter isolates TXT lookups?',
                options: ['dns.qry.type == 16', 'dns.qry.type == 1', 'dns.qry.type == 28'],
                answer: 0,
                explain: 'TXT is query type 16. Type 1 is A and type 28 is AAAA.'
            }
        },
        'c2-http': {
            text: 'Read the fallback Host',
            quiz: {
                q: 'Which field shows the Host of the fallback channel?',
                options: ['http.host', 'tcp.port', 'icmp.type'],
                answer: 0,
                explain: 'http.host exposes the Host header, which identifies fallback.c2.example in the HTTP check-in.'
            }
        },
        'c2-icmp': {
            text: 'Name the echo request',
            quiz: {
                q: 'Which ICMP type is an echo request?',
                options: ['0', '8', '3'],
                answer: 1,
                explain: 'Type 8 is an echo request and type 0 is the echo reply. Type 3 is destination unreachable.'
            }
        },
        'c2-jitter': {
            text: 'Plot the rhythm',
            quiz: {
                q: 'Which view shows traffic volume over time?',
                options: ['IO Graph', 'Protocol Hierarchy', 'Expert Information'],
                answer: 0,
                explain: 'IO Graph plots packets or bytes against time, which makes regular beacon intervals easy to see.'
            }
        },
        'c2-case': {
            text: 'Count the TLS records',
            quiz: {
                q: 'How many TLS records does this C2 capture contain?',
                options: ['2', '6', '12'],
                answer: 1,
                explain: 'The two beacon sessions contribute six TLS records in total.'
            }
        }
    };

    CHAPTERS.forEach(function (chapter) {
        chapter.missions.forEach(function (mission) {
            var extra = EXTRA_QUIZZES[mission.id];
            if (!extra) return;
            var quizIndex = -1;
            for (var i = 0; i < mission.tasks.length; i++) {
                if (mission.tasks[i].quiz) { quizIndex = i; break; }
            }
            if (quizIndex === -1) mission.tasks.push(extra);
            else mission.tasks.splice(quizIndex, 0, extra);
        });
    });

    var EXTRA_QUIZZES_2 = {
        'first-packet': {
            text: 'Read the summary row',
            quiz: {
                q: 'What does one row in the packet list summarise?',
                options: ['The full hex of the frame', 'Frame number, protocol and a one-line description', 'Only the destination MAC address'],
                answer: 1,
                explain: 'A packet-list row gives the frame number, time, addresses, protocol and a short Info summary. The full bytes live in the bottom pane.'
            }
        },
        'read-columns': {
            text: 'Find the frame size',
            quiz: {
                q: 'Which column reports the size of a frame in bytes?',
                options: ['No.', 'Length', 'Protocol'],
                answer: 1,
                explain: 'Length is the frame size on the wire. No. is the frame number and Protocol is the highest decoded protocol.'
            }
        },
        'one-story': {
            text: 'First step of a web visit',
            quiz: {
                q: 'Which packet comes first in this classic web session?',
                options: ['ARP', 'HTTP response', 'TCP FIN'],
                answer: 0,
                explain: 'ARP resolves the gateway MAC first. DNS, the TCP handshake and HTTP follow.'
            }
        },
        'ping-pong': {
            text: 'Name the ping protocol',
            quiz: {
                q: 'Which protocol does the ping command use?',
                options: ['TCP', 'UDP', 'ICMP'],
                answer: 2,
                explain: 'Ping sends ICMP echo requests and receives echo replies. It has no TCP or UDP ports.'
            }
        },
        'filter-protocol': {
            text: 'Ask for ARP only',
            quiz: {
                q: 'Which filter keeps only ARP packets?',
                options: ['arp', 'ip', 'tcp'],
                answer: 0,
                explain: 'A bare protocol name such as arp is a display filter. It keeps only frames that contain ARP.'
            }
        },
        'filter-address': {
            text: 'Send only from one host',
            quiz: {
                q: 'Which filter matches only packets sent by 10.0.0.1?',
                options: ['ip.addr == 10.0.0.1', 'ip.src == 10.0.0.1', 'ip.dst == 10.0.0.1'],
                answer: 1,
                explain: 'ip.src is directional and matches the sender. ip.addr would match either endpoint.'
            }
        },
        'filter-logic': {
            text: 'Hide ARP and DNS',
            quiz: {
                q: 'Which expression shows everything except ARP and DNS?',
                options: ['arp || dns', '!(arp || dns)', 'arp && dns'],
                answer: 1,
                explain: 'The ! operator inverts the grouped expression, so !(arp || dns) excludes both protocols.'
            }
        },
        'filter-challenge': {
            text: 'Name both responses',
            quiz: {
                q: 'Which two response types does this challenge combine?',
                options: ['ARP and ICMP', 'DNS and HTTP', 'TCP and TLS'],
                answer: 1,
                explain: 'The filter joins a DNS response with an HTTP response, proving that one expression can mix protocols.'
            }
        },
        'port-story': {
            text: 'Find the HTTPS port',
            quiz: {
                q: 'Which well-known port does HTTPS normally use?',
                options: ['53', '80', '443'],
                answer: 2,
                explain: 'HTTPS uses TCP 443. Port 53 is DNS and port 80 is plain HTTP.'
            }
        },
        'dns-detail': {
            text: 'Match query to answer',
            quiz: {
                q: 'Which field ties a DNS response to its query?',
                options: ['Transaction ID', 'TTL', 'Record type'],
                answer: 0,
                explain: 'The transaction ID is copied from the query into the response so the client can pair them.'
            }
        },
        'tcp-handshake': {
            text: 'Isolate initial SYNs',
            quiz: {
                q: 'Which filter finds SYNs that are not acknowledgements?',
                options: ['tcp.flags.syn == 1', 'tcp.flags.syn == 1 && tcp.flags.ack == 0', 'tcp.flags.ack == 1'],
                answer: 1,
                explain: 'The first handshake packet has SYN set and ACK clear. Adding tcp.flags.ack == 0 excludes SYN/ACK replies.'
            }
        },
        'tls-sni': {
            text: 'Why servers need SNI',
            quiz: {
                q: 'What does the server use SNI for?',
                options: ['To choose the right certificate or site to serve', 'To encrypt the HTTP body', 'To assign a TCP port'],
                answer: 0,
                explain: 'One server address can host many sites. SNI tells it which certificate and virtual host the client expects.'
            }
        },
        'follow-stream': {
            text: 'Why reassembly helps',
            quiz: {
                q: 'Why is Follow Stream faster than reading packet by packet?',
                options: ['It reassembles the payload in both directions', 'It decrypts TLS automatically', 'It filters out retransmissions permanently'],
                answer: 0,
                explain: 'Follow Stream rebuilds the ordered application payload for both sides, so you read the conversation instead of individual frames.'
            }
        },
        'hierarchy': {
            text: 'What the hierarchy measures',
            quiz: {
                q: 'What does Protocol Hierarchy show for each protocol?',
                options: ['Its share of packets and bytes', 'Its encryption keys', 'Only its port numbers'],
                answer: 0,
                explain: 'Protocol Hierarchy reports packet and byte counts per protocol, which makes unexpected traffic stand out.'
            }
        },
        'conversations': {
            text: 'Find the heavy talker',
            quiz: {
                q: 'Which Conversations column identifies the host moving the most data?',
                options: ['Start time', 'Bytes', 'Port'],
                answer: 1,
                explain: 'Sorting by Bytes shows which address or conversation transferred the most data.'
            }
        },
        'io-graph': {
            text: 'Read a flat line',
            quiz: {
                q: 'What does a flat line in an IO Graph mean?',
                options: ['No traffic in that interval', 'A protocol error', 'A retransmission'],
                answer: 0,
                explain: 'The graph plots volume over time. A flat segment means nothing was captured during that interval.'
            }
        },
        'make-it-yours': {
            text: 'Add a field column',
            quiz: {
                q: 'Which menu adds a column built from a protocol field?',
                options: ['View → Columns', 'Statistics → Endpoints', 'Edit → Find Packet'],
                answer: 0,
                explain: 'View → Columns lets you add a column whose value comes from any field, such as tcp.stream or http.host.'
            }
        },
        'nxdomain': {
            text: 'Spot a successful lookup',
            quiz: {
                q: 'Which DNS RCODE value means success?',
                options: ['0', '3', '5'],
                answer: 0,
                explain: 'RCODE 0 is no error. 3 is NXDOMAIN and 5 is refused.'
            }
        },
        'connection-refused': {
            text: 'What an open port returns',
            quiz: {
                q: 'What does an open TCP port return to a SYN?',
                options: ['RST/ACK', 'SYN/ACK', 'ICMP echo'],
                answer: 1,
                explain: 'An open port accepts the connection with SYN/ACK. A closed port answers with RST/ACK.'
            }
        },
        'zero-window': {
            text: 'How the stall clears',
            quiz: {
                q: 'What clears a zero-window stall?',
                options: ['A window update after the application reads data', 'A DNS response', 'A new ARP reply'],
                answer: 0,
                explain: 'When the receiving application drains its buffer, TCP advertises a larger window and the sender resumes.'
            }
        },
        'port-unreachable': {
            text: 'What the error quotes',
            quiz: {
                q: 'What does the ICMP unreachable payload quote?',
                options: ['The original IP header and first bytes', 'The server certificate', 'The DNS question'],
                answer: 0,
                explain: 'ICMP errors include the start of the packet that triggered them, so you can match the error to its original flow.'
            }
        },
        'tls-alert': {
            text: 'Find the alert content type',
            quiz: {
                q: 'Which TLS content type carries an alert?',
                options: ['21', '22', '23'],
                answer: 0,
                explain: 'Content type 21 is Alert, 22 is Handshake and 23 is Application Data.'
            }
        },
        'case-file': {
            text: 'Why marks survive',
            quiz: {
                q: 'Why mark packets during an investigation?',
                options: ['Marks stay highlighted when filters change', 'Marks delete the packet', 'Marks decrypt the payload'],
                answer: 0,
                explain: 'Marks are independent of display filters, so evidence stays marked while you narrow or widen the view.'
            }
        },
        'retransmission': {
            text: 'Receiver behaviour',
            quiz: {
                q: 'What does the receiver do with a retransmitted segment?',
                options: ['Keeps the first copy and discards the duplicate', 'Accepts both copies', 'Closes the connection'],
                answer: 0,
                explain: 'The receiver already has those bytes, so the duplicate is discarded. The transfer only lost time and bandwidth.'
            }
        },
        'dup-acks': {
            text: 'What a duplicate ACK says',
            quiz: {
                q: 'What does a duplicate ACK acknowledge?',
                options: ['The last contiguous byte received', 'The missing byte it wants', 'The next connection'],
                answer: 0,
                explain: 'The receiver repeats the last in-order byte it has, which tells the sender that something after it is missing.'
            }
        },
        'fragments': {
            text: 'Find the final piece',
            quiz: {
                q: 'Which fragment clears the More Fragments flag?',
                options: ['The first fragment', 'The last fragment', 'Every fragment'],
                answer: 1,
                explain: 'The last fragment has More Fragments clear. Earlier fragments keep it set so the destination knows more are coming.'
            }
        },
        'slow-transfer': {
            text: 'Measure the conversation',
            quiz: {
                q: 'Which view reports bytes exchanged per address/port pair?',
                options: ['Conversations', 'Coloring Rules', 'Protocol Hierarchy'],
                answer: 0,
                explain: 'Conversations lists duration, packets and bytes for each pair. Protocol Hierarchy only totals by protocol.'
            }
        },
        'arp-spoof': {
            text: 'What spoofing enables',
            quiz: {
                q: 'What does ARP spoofing usually enable?',
                options: ['Man-in-the-middle traffic capture', 'Faster DNS resolution', 'Automatic TLS upgrades'],
                answer: 0,
                explain: 'By claiming the gateway address, the attacker can position itself in the path and observe or alter traffic.'
            }
        },
        'port-scan': {
            text: 'What an open port returns',
            quiz: {
                q: 'What does an open port return to a scan SYN?',
                options: ['SYN/ACK', 'RST/ACK', 'No response ever'],
                answer: 0,
                explain: 'An open port accepts with SYN/ACK. A closed port returns RST/ACK, which is why a burst of resets reveals the scan.'
            }
        },
        'dns-tunnel': {
            text: 'Spot the tunnel pattern',
            quiz: {
                q: 'Which pattern hints at DNS tunnelling?',
                options: ['Long encoded labels under one parent domain', 'Short names for popular websites', 'Repeated PTR lookups for local hosts'],
                answer: 0,
                explain: 'Encoded chunks and a shared parent domain let malware move data through DNS without raising ordinary browsing noise.'
            }
        },
        'malicious-upload': {
            text: 'Name the binary type',
            quiz: {
                q: 'Which Content-Type marks a generic binary upload?',
                options: ['application/octet-stream', 'text/html', 'application/json'],
                answer: 0,
                explain: 'application/octet-stream is the generic binary type. A POST with this type to an unknown host deserves escalation.'
            }
        },
        'c2-sni': {
            text: 'Link the infrastructure',
            quiz: {
                q: 'Why compare the TLS SNI with DNS and HTTP?',
                options: ['To link the same infrastructure across protocols', 'To decrypt the TLS session', 'To find the client MAC address'],
                answer: 0,
                explain: 'Matching hostnames and addresses across DNS, HTTP and TLS shows that separate channels reach the same controller.'
            }
        },
        'threat-case': {
            text: 'Find the redirect evidence',
            quiz: {
                q: 'Which packet explains why traffic was redirected?',
                options: ['The spoofed ARP reply (#3)', 'The HTTP response (#10)', 'The DNS query (#2)'],
                answer: 0,
                explain: 'The forged ARP reply maps the gateway IP to the attacker MAC, which is the redirection evidence in this case.'
            }
        },
        'v6-neighbours': {
            text: 'How IPv6 discovers neighbours',
            quiz: {
                q: 'Which address type does IPv6 Neighbor Discovery use instead of broadcast?',
                options: ['Solicited-node multicast', 'The all-hosts broadcast', 'A public anycast address'],
                answer: 0,
                explain: 'IPv6 has no broadcast. Neighbor Solicitation goes to a solicited-node multicast address derived from the target address.'
            }
        },
        'v6-router': {
            text: 'Ask the router',
            quiz: {
                q: 'Which ICMPv6 type is Router Solicitation?',
                options: ['133', '134', '135'],
                answer: 0,
                explain: 'Type 133 is Router Solicitation, 134 is Router Advertisement and 135 is Neighbor Solicitation.'
            }
        },
        'v6-aaaa': {
            text: 'Filter the AAAA lookup',
            quiz: {
                q: 'Which filter selects AAAA queries and answers?',
                options: ['dns.qry.type == 1', 'dns.qry.type == 28', 'dns.qry.type == 16'],
                answer: 1,
                explain: 'AAAA is query type 28. Type 1 is A and type 16 is TXT.'
            }
        },
        'v6-tls': {
            text: 'Isolate the Client Hello',
            quiz: {
                q: 'Which filter isolates TLS Client Hellos?',
                options: ['tls.handshake.type == 1', 'tls.handshake.type == 2', 'tls.record.version == 1'],
                answer: 0,
                explain: 'Handshake type 1 is Client Hello. Type 2 is Server Hello.'
            }
        },
        'v6-hop-limit': {
            text: 'Filter the doomed hop',
            quiz: {
                q: 'Which filter finds packets with a hop limit of 1?',
                options: ['ipv6.hlim == 1', 'ipv6.hlim == 255', 'ip.ttl == 1'],
                answer: 0,
                explain: 'ipv6.hlim is the IPv6 hop limit. The next router discards a packet with value 1 and returns Time Exceeded.'
            }
        },
        'web-login': {
            text: 'Submit the form',
            quiz: {
                q: 'Which HTTP method normally submits a login form?',
                options: ['GET', 'POST', 'HEAD'],
                answer: 1,
                explain: 'POST carries the form body, including the username and password. GET puts data in the URL and HEAD has no body.'
            }
        },
        'web-redirect': {
            text: 'Read the 302',
            quiz: {
                q: 'What does HTTP status 302 mean?',
                options: ['Found — a temporary redirect', 'Unauthorized', 'Server error'],
                answer: 0,
                explain: '302 Found is a temporary redirect. The browser reads the Location header to find the next URL.'
            }
        },
        'web-cookies': {
            text: 'Send the cookie back',
            quiz: {
                q: 'Which request header sends a stored cookie to the server?',
                options: ['Set-Cookie', 'Cookie', 'Location'],
                answer: 1,
                explain: 'The browser returns stored values in the Cookie header. Set-Cookie is used by the server to create them.'
            }
        },
        'web-tracking': {
            text: 'Name the tracker',
            quiz: {
                q: 'Which host is the third-party tracker in this capture?',
                options: ['metrics.example.org', 'shop.example.com', 'cdn.example.net'],
                answer: 0,
                explain: 'The pixel is requested from metrics.example.org while the user visits the shop, which makes it third-party tracking.'
            }
        },
        'web-download': {
            text: 'Find the saved name',
            quiz: {
                q: 'Which response header names the file being downloaded?',
                options: ['Content-Disposition', 'Content-Type', 'User-Agent'],
                answer: 0,
                explain: 'Content-Disposition carries the suggested filename. Content-Type only describes the media type.'
            }
        },
        'web-case': {
            text: 'Count the requests',
            quiz: {
                q: 'How many HTTP request packets does this capture contain?',
                options: ['3', '6', '12'],
                answer: 1,
                explain: 'The capture splits evenly into six requests and six responses.'
            }
        },
        'tls-hellos': {
            text: 'Count the hellos',
            quiz: {
                q: 'How many TLS Client Hellos are in this capture?',
                options: ['1', '3', '12'],
                answer: 1,
                explain: 'Packets #10, #20 and #30 are the three Client Hellos, one per session.'
            }
        },
        'tls-server-flight': {
            text: 'Count the certificates',
            quiz: {
                q: 'How many certificate messages are in this capture?',
                options: ['1', '3', '6'],
                answer: 1,
                explain: 'Each of the three TLS sessions sends one Certificate message, so there are three in total.'
            }
        },
        'tls-sni-audit': {
            text: 'Name the suspicious host',
            quiz: {
                q: 'Which SNI looks like a disguised update service?',
                options: ['updates.bad-cdn.example', 'telemetry.example.com', 'shop.example.com'],
                answer: 0,
                explain: 'updates.bad-cdn.example imitates an update domain while the bad-cdn label marks it as suspicious.'
            }
        },
        'tls-alert-case': {
            text: 'Filter the failure',
            quiz: {
                q: 'Which filter isolates the handshake_failure alert?',
                options: ['tls.alert.description == 40', 'tls.alert.severity == 1', 'tls.handshake.type == 40'],
                answer: 0,
                explain: 'Alert description 40 is handshake_failure. Severity 1 is only a warning, not this fatal alert.'
            }
        },
        'tls-legacy': {
            text: 'Filter the legacy session',
            quiz: {
                q: 'Which filter finds TLS 1.0 records?',
                options: ['tls.record.version == 0x0303', 'tls.record.version == 0x0301', 'tls.record.version == 0x0304'],
                answer: 1,
                explain: 'TLS 1.0 records carry version 0x0301. 0x0303 is TLS 1.2 and 0x0304 is TLS 1.3.'
            }
        },
        'tls-case': {
            text: 'Count every record',
            quiz: {
                q: 'How many TLS records does this capture contain?',
                options: ['3', '6', '12'],
                answer: 2,
                explain: 'The bare tls filter returns all twelve TLS records across the three sessions.'
            }
        },
        'mal-dga': {
            text: 'Why malware uses a DGA',
            quiz: {
                q: 'What is the purpose of a domain generation algorithm?',
                options: ['To generate many candidate controller domains', 'To speed up DNS caching', 'To encrypt executable files'],
                answer: 0,
                explain: 'A DGA produces many pseudo-random names so the implant can find its controller even when domains are taken down.'
            }
        },
        'mal-payload': {
            text: 'Filter generic binaries',
            quiz: {
                q: 'Which filter finds downloads with a generic binary content type?',
                options: ['http.content_type contains octet-stream', 'http.request.method == "GET"', 'http.host contains update'],
                answer: 0,
                explain: 'application/octet-stream is the generic binary type, so matching it surfaces likely executable downloads.'
            }
        },
        'mal-user-agent': {
            text: 'Name the scripted client',
            quiz: {
                q: 'Which User-Agent reveals a scripted Windows HTTP client?',
                options: ['WinHttp.WinHttpRequest', 'Mozilla/5.0 Firefox', 'curl/8.0'],
                answer: 0,
                explain: 'WinHttp.WinHttpRequest is a Windows library often used by malware, not the string a normal browser sends.'
            }
        },
        'mal-beacon': {
            text: 'Read the beacon host',
            quiz: {
                q: 'Which hostname appears in the beacon SNI?',
                options: ['api.sync-telemetry.xyz', 'update-checker.top', 'exfil.evil-cdn.top'],
                answer: 0,
                explain: 'The Client Hello requests api.sync-telemetry.xyz, a telemetry-sounding name on an unrelated address.'
            }
        },
        'mal-exfil': {
            text: 'Name the collecting domain',
            quiz: {
                q: 'Which parent domain collects the exfiltration chunks?',
                options: ['exfil.evil-cdn.top', 'update-checker.top', 'api.sync-telemetry.xyz'],
                answer: 0,
                explain: 'Chunks such as chunk1.exfil.evil-cdn.top share the parent exfil.evil-cdn.top, tying them into one exfiltration channel.'
            }
        },
        'mal-gate': {
            text: 'Read the endpoint path',
            quiz: {
                q: 'Which field shows the path of the gate script?',
                options: ['http.request.uri', 'http.host', 'http.user_agent'],
                answer: 0,
                explain: 'http.request.uri carries the requested path, which is where the gate script receives the check-in.'
            }
        },
        'mal-case': {
            text: 'Gather the C2 traffic',
            quiz: {
                q: 'Which filter gathers every packet to or from the C2 host?',
                options: ['ip.addr == 198.51.100.77', 'tcp.port == 80', 'dns.qry.type == 16'],
                answer: 0,
                explain: 'ip.addr matches either endpoint, so it returns the TLS beacon, the gate POST and the DNS exfiltration to that controller.'
            }
        },
        'c2-heartbeat': {
            text: 'Count the sessions',
            quiz: {
                q: 'How many separate beacon sessions are in this capture?',
                options: ['1', '2', '6'],
                answer: 1,
                explain: 'Two TCP sessions each carry a Client Hello for beacon.c2.example, which shows the scheduled check-ins.'
            }
        },
        'c2-dns': {
            text: 'Why the chunks are numbered',
            quiz: {
                q: 'What do the chunk1, chunk2 labels reveal?',
                options: ['Ordered data chunks under one parent domain', 'Separate unrelated websites', 'DNS cache misses'],
                answer: 0,
                explain: 'Numbered labels give the chunks an order, while the shared parent domain shows they form one tunnel.'
            }
        },
        'c2-http': {
            text: 'Spot the scripted client',
            quiz: {
                q: 'Which User-Agent hints at a scripted HTTP client?',
                options: ['curl/8.0', 'Mozilla/5.0 Chrome', 'Mozilla/5.0 Firefox'],
                answer: 0,
                explain: 'A bare curl string is a tool fingerprint, not a normal desktop browser, which fits an automated fallback channel.'
            }
        },
        'c2-icmp': {
            text: 'Why the pings look automated',
            quiz: {
                q: 'Why do fixed identifiers and regular sequence numbers suggest automation?',
                options: ['They look like a scripted beacon, not a person running ping', 'They prove the host is offline', 'They encrypt the ICMP payload'],
                answer: 0,
                explain: 'A person running ping produces irregular timing. A fixed identifier and steady sequence indicate a programmed keepalive.'
            }
        },
        'c2-jitter': {
            text: 'Measure each pair',
            quiz: {
                q: 'Which view reports bytes exchanged per pair?',
                options: ['Conversations', 'IO Graph', 'Protocol Hierarchy'],
                answer: 0,
                explain: 'Conversations reports duration, packet count and bytes for each pair. IO Graph shows volume over time, not per-pair totals.'
            }
        },
        'c2-case': {
            text: 'Preserve the beacon evidence',
            quiz: {
                q: 'Which two packets preserve the beacon SNI evidence?',
                options: ['#6 and #41', '#17 and #24', '#1 and #2'],
                answer: 0,
                explain: 'The two Client Hellos at #6 and #41 both request beacon.c2.example, so marking them keeps the channel evidence.'
            }
        }
    };

    CHAPTERS.forEach(function (chapter) {
        chapter.missions.forEach(function (mission) {
            var extra = EXTRA_QUIZZES_2[mission.id];
            if (!extra) return;
            var quizIndex = -1;
            for (var i = 0; i < mission.tasks.length; i++) {
                if (mission.tasks[i].quiz) { quizIndex = i; break; }
            }
            if (quizIndex === -1) mission.tasks.push(extra);
            else mission.tasks.splice(quizIndex, 0, extra);
        });
    });

    var CHAPTER_CHALLENGES = {
        ch1: [
            {
                challenge: true,
                text: 'read the session order',
                quiz: {
                    q: 'Packets #2, #3, #5 and #8 appear in that order. Which conclusion is correct?',
                    options: [
                        'The client resolved the name before opening the TCP connection',
                        'The HTTP response arrived before the DNS query',
                        'ARP used TCP port 53 to find the server'
                    ],
                    answer: 0,
                    explain: 'ARP finds the gateway, DNS resolves the name, the TCP handshake opens the connection and HTTP follows. The response cannot arrive before the request.'
                }
            },
            {
                challenge: true,
                text: 'pair the echo messages',
                quiz: {
                    q: 'The reply says "(request in 12)". Which fields did Wireshark use to pair them?',
                    options: [
                        'The ICMP identifier and sequence number',
                        'The TCP source and destination ports',
                        'The Ethernet source and destination MAC addresses'
                    ],
                    answer: 0,
                    explain: 'ICMP has no ports. Wireshark pairs echo requests and replies by identifier and sequence number.'
                }
            }
        ],
        ch2: [
            {
                challenge: true,
                text: 'combine direction and protocol',
                quiz: {
                    q: 'Which filter keeps DNS packets in either direction while excluding DNS over TCP?',
                    options: [
                        'udp.port == 53',
                        'tcp.port == 53',
                        'dns && tcp.port == 53'
                    ],
                    answer: 0,
                    explain: 'udp.port == 53 matches UDP DNS in both directions. The other filters either target TCP DNS or require TCP for every DNS packet.'
                }
            },
            {
                challenge: true,
                text: 'be precise about direction',
                quiz: {
                    q: 'You need packets sent by 10.0.0.1 to the web server on port 80 only. Which filter is most precise?',
                    options: [
                        'ip.src == 10.0.0.1 && tcp.dstport == 80',
                        'ip.addr == 10.0.0.1 && tcp.port == 80',
                        'ip.src == 10.0.0.1 || tcp.dstport == 80'
                    ],
                    answer: 0,
                    explain: 'The first expression requires the sender to be 10.0.0.1 and the destination port to be 80. ip.addr and tcp.port match either direction, and || matches too much.'
                }
            }
        ],
        ch3: [
            {
                challenge: true,
                text: 'separate readable metadata',
                quiz: {
                    q: 'A TLS session shows a readable SNI and then only Application Data. Which statement is true?',
                    options: [
                        'The hostname is visible because the Client Hello is sent before encryption',
                        'The certificate is encrypted in every TLS version',
                        'TLS hides the destination IP address'
                    ],
                    answer: 0,
                    explain: 'SNI travels in the clear inside the Client Hello. The destination IP is still visible in the IP header, and certificates remain readable in TLS 1.2.'
                }
            },
            {
                challenge: true,
                text: 'isolate the server reply',
                quiz: {
                    q: 'Which filter returns the server SYN/ACK but not the client initial SYN?',
                    options: [
                        'tcp.flags.syn == 1 && tcp.flags.ack == 1',
                        'tcp.flags.syn == 1',
                        'tcp.flags.ack == 1'
                    ],
                    answer: 0,
                    explain: 'A SYN/ACK has both flags set. tcp.flags.syn == 1 also returns the first SYN, and tcp.flags.ack == 1 returns ordinary ACKs and data packets.'
                }
            }
        ],
        ch4: [
            {
                challenge: true,
                text: 'measure and preserve evidence',
                quiz: {
                    q: 'You must find the heaviest conversation and keep two frames as evidence across filters. Which combination works?',
                    options: [
                        'Sort Conversations by bytes, then mark frames with Ctrl+M',
                        'Open IO Graph and delete the busiest row',
                        'Use Coloring Rules to remove packets from the capture'
                    ],
                    answer: 0,
                    explain: 'Conversations reports bytes per pair, and marks survive filter changes. Coloring and graphs do not delete evidence.'
                }
            },
            {
                challenge: true,
                text: 'interpret the graph',
                quiz: {
                    q: 'An IO Graph shows one spike followed by a long flat section. What is the best reading?',
                    options: [
                        'A short burst of traffic followed by idle time',
                        'Continuous heavy traffic for the whole capture',
                        'The capture ended with a protocol error'
                    ],
                    answer: 0,
                    explain: 'The graph plots volume over time. A spike is a burst and the flat section means no traffic was captured in that interval.'
                }
            }
        ],
        ch5: [
            {
                challenge: true,
                text: 'interpret the reset',
                quiz: {
                    q: 'A flow shows SYN, then RST/ACK from the server. What is the most accurate finding?',
                    options: [
                        'The destination port is closed or refused',
                        'The TCP handshake completed successfully',
                        'The server sent application data after the SYN'
                    ],
                    answer: 0,
                    explain: 'RST/ACK immediately after a SYN means no listener accepted the connection. A completed handshake would show SYN/ACK, then ACK.'
                }
            },
            {
                challenge: true,
                text: 'connect the expert warnings',
                quiz: {
                    q: 'Which pair of expert warnings best supports a stalled HTTP transfer?',
                    options: [
                        'A zero window and a later window update',
                        'An NXDOMAIN response and an ARP reply',
                        'A TLS alert and an ICMP echo request'
                    ],
                    answer: 0,
                    explain: 'A zero window pauses the sender until the receiver advertises a larger window. The other pairs are unrelated failure types.'
                }
            }
        ],
        ch6: [
            {
                challenge: true,
                text: 'diagnose the duplicate',
                quiz: {
                    q: 'The same TCP sequence number and payload appear twice 150 ms apart. What is the best diagnosis?',
                    options: [
                        'A retransmission caused by a missing or delayed ACK',
                        'Two independent connections to the same server',
                        'A DNS retry using TCP'
                    ],
                    answer: 0,
                    explain: 'A repeated sequence number with the same payload is a retransmission. Two connections would use different source ports and sequence spaces.'
                }
            },
            {
                challenge: true,
                text: 'predict the recovery',
                quiz: {
                    q: 'Three duplicate ACKs arrive for the same ACK number. What does TCP do next?',
                    options: [
                        'Fast retransmit the missing segment',
                        'Reset the connection with RST',
                        'Start a new three-way handshake'
                    ],
                    answer: 0,
                    explain: 'Three duplicate ACKs tell the sender that a segment is missing, so it retransmits immediately without waiting for a timeout.'
                }
            }
        ],
        ch7: [
            {
                challenge: true,
                text: 'act on the ARP evidence',
                quiz: {
                    q: 'An ARP reply maps the gateway IP to a MAC that differs from the baseline. What is the strongest next step?',
                    options: [
                        'Treat it as possible ARP spoofing and compare MACs with the baseline',
                        'Ignore it because ARP replies are authenticated',
                        'Delete all HTTP traffic from the capture'
                    ],
                    answer: 0,
                    explain: 'ARP has no authentication. A gateway IP announced from a new MAC is the classic spoofing signature, so validate it against the known gateway MAC.'
                }
            },
            {
                challenge: true,
                text: 'classify the scan',
                quiz: {
                    q: 'One host sends SYNs to nine ports and receives RST/ACK from each. What does this most likely represent?',
                    options: [
                        'A port scan against closed ports',
                        'A completed HTTP session',
                        'A DNS zone transfer'
                    ],
                    answer: 0,
                    explain: 'Many SYNs to different ports followed by resets is a vertical port scan. An open port would answer with SYN/ACK.'
                }
            }
        ],
        ch8: [
            {
                challenge: true,
                text: 'find the router',
                quiz: {
                    q: 'An IPv6 host needs its default router link-layer address. Which messages are relevant?',
                    options: [
                        'Router Solicitation and Router Advertisement (types 133 and 134)',
                        'Neighbor Solicitation only (type 135)',
                        'ARP request and ARP reply'
                    ],
                    answer: 0,
                    explain: 'Router Solicitation asks for a router and Router Advertisement answers with prefix and link-layer details. IPv6 does not use ARP.'
                }
            },
            {
                challenge: true,
                text: 'follow the expiring hop',
                quiz: {
                    q: 'A packet with Hop Limit 1 reaches a router. Which evidence should appear next?',
                    options: [
                        'An ICMPv6 Time Exceeded message from the router',
                        'A TCP RST from the final destination',
                        'A DNS NXDOMAIN response'
                    ],
                    answer: 0,
                    explain: 'The router decrements the Hop Limit to zero, discards the packet and returns ICMPv6 Time Exceeded.'
                }
            }
        ],
        ch9: [
            {
                challenge: true,
                text: 'follow the session state',
                quiz: {
                    q: 'A login POST is followed by Set-Cookie: session=abc123 and a 302 to /account. What does the cookie represent?',
                    options: [
                        'A session token the browser will send on later requests',
                        'The redirect target for the next page',
                        'The server TLS certificate'
                    ],
                    answer: 0,
                    explain: 'Set-Cookie creates the session token. The browser returns it in the Cookie header, while Location carries the redirect target.'
                }
            },
            {
                challenge: true,
                text: 'triage the download',
                quiz: {
                    q: 'A download is application/octet-stream with filename update.exe and a body starting with MZ. What are the two strongest findings?',
                    options: [
                        'A Windows executable download with a suggested filename',
                        'A harmless HTML page with a redirect',
                        'A DNS TXT record carrying text'
                    ],
                    answer: 0,
                    explain: 'The MZ signature confirms a Windows executable, and Content-Disposition names the saved file update.exe.'
                }
            }
        ],
        ch10: [
            {
                challenge: true,
                text: 'combine the TLS evidence',
                quiz: {
                    q: 'One session shows a suspicious SNI, a fatal handshake_failure alert and record version 0x0301. Which summary is best?',
                    options: [
                        'A legacy TLS session to a suspicious host that failed its handshake',
                        'A successful TLS 1.3 download from a trusted host',
                        'A plaintext HTTP login with no encryption'
                    ],
                    answer: 0,
                    explain: '0x0301 is TLS 1.0, alert description 40 is handshake_failure, and the SNI identifies the suspicious host.'
                }
            },
            {
                challenge: true,
                text: 'list the visible metadata',
                quiz: {
                    q: 'Which metadata stays readable even when TLS application data is encrypted?',
                    options: [
                        'SNI, certificate details, record versions and alerts',
                        'The HTTP body and cookie values',
                        'The user password and session token'
                    ],
                    answer: 0,
                    explain: 'Handshake metadata is sent before or outside the encrypted application records. The HTTP body, cookies and credentials are protected.'
                }
            }
        ],
        ch11: [
            {
                challenge: true,
                text: 'identify the controller',
                quiz: {
                    q: 'The capture shows NXDOMAIN bursts, an MZ download, a telemetry-looking TLS SNI and TXT chunks. Which stage identifies the controller hostname?',
                    options: [
                        'The TLS SNI in the Client Hello',
                        'The NXDOMAIN replies from failed lookups',
                        'The MZ header in the downloaded file'
                    ],
                    answer: 0,
                    explain: 'The SNI names the host the implant contacted. NXDOMAIN replies are failed guesses and the MZ header only identifies an executable.'
                }
            },
            {
                challenge: true,
                text: 'confirm the payload type',
                quiz: {
                    q: 'Why does the MZ signature matter even though the file arrived over HTTP?',
                    options: [
                        'It confirms the body is a Windows executable',
                        'It proves the web server is patched',
                        'It encrypts the rest of the download'
                    ],
                    answer: 0,
                    explain: 'MZ is the DOS/PE header. Seeing it in the response body confirms the download is an executable, not a document or image.'
                }
            }
        ],
        ch12: [
            {
                challenge: true,
                text: 'assess the channel set',
                quiz: {
                    q: 'HTTPS, HTTP, DNS TXT and ICMP all reach 198.51.100.77. What is the best assessment?',
                    options: [
                        'A multi-channel C2 implant using fallbacks',
                        'Four unrelated users browsing normally',
                        'A DNS server outage affecting one subnet'
                    ],
                    answer: 0,
                    explain: 'Several protocols reaching one controller is resilient C2. The plain HTTP and ICMP channels act as fallbacks when HTTPS is blocked.'
                }
            },
            {
                challenge: true,
                text: 'link the channels',
                quiz: {
                    q: 'Which evidence most directly links the HTTPS beacon and the ICMP keepalive to one controller?',
                    options: [
                        'Both use the same destination IP 198.51.100.77',
                        'Both use TCP port 443',
                        'Both share the same Ethernet source address'
                    ],
                    answer: 0,
                    explain: 'ICMP has no ports, so the shared destination address is what ties the channels together. The Ethernet source belongs to the victim.'
                }
            }
        ]
    };

    CHAPTERS.forEach(function (chapter) {
        var tasks = CHAPTER_CHALLENGES[chapter.id];
        if (!tasks || !chapter.missions.length) return;
        var capstone = chapter.missions[chapter.missions.length - 1];
        tasks.forEach(function (task) { capstone.tasks.push(task); });
    });

    var CHAPTER_CHALLENGES_2 = {
        ch1: [
            {
                challenge: true,
                text: 'Prove the gateway replied',
                quiz: {
                    q: 'Which pair of packets proves the client learned the gateway MAC address?',
                    options: [
                        'The ARP request and the ARP reply',
                        'The DNS query and the DNS response',
                        'The client SYN and the server SYN/ACK'
                    ],
                    answer: 0,
                    explain: 'ARP asks who owns the gateway IP and the reply supplies the MAC. DNS and TCP happen only after that mapping is known.'
                }
            },
            {
                challenge: true,
                text: 'Explain the protocol column',
                quiz: {
                    q: 'Why does packet #8 show Protocol=HTTP even though Ethernet and IP are present?',
                    options: [
                        'The column shows the highest decoded protocol',
                        'HTTP replaces Ethernet on the wire',
                        'The frame has no IP header'
                    ],
                    answer: 0,
                    explain: 'The Protocol column reports the highest-layer protocol Wireshark decoded. Ethernet and IP are still visible in the details pane.'
                }
            }
        ],
        ch2: [
            {
                challenge: true,
                text: 'Combine host and transport',
                quiz: {
                    q: 'Which filter finds TCP packets where either endpoint is 203.0.113.10?',
                    options: [
                        'ip.addr == 203.0.113.10 && tcp',
                        'ip.src == 203.0.113.10 && tcp',
                        'tcp.port == 203.0.113.10'
                    ],
                    answer: 0,
                    explain: 'ip.addr matches either endpoint and && tcp limits the result to TCP. Using the IP as a port is invalid.'
                }
            },
            {
                challenge: true,
                text: 'Keep queries, hide replies',
                quiz: {
                    q: 'Which filter keeps DNS queries but hides DNS responses?',
                    options: [
                        'dns && dns.flags.response == 0',
                        'dns.flags.response == 1',
                        '!dns'
                    ],
                    answer: 0,
                    explain: 'Queries have the response flag clear. The first filter keeps DNS and requires response == 0, so only queries remain.'
                }
            }
        ],
        ch3: [
            {
                challenge: true,
                text: 'Find connection openers',
                quiz: {
                    q: 'Which filter returns the first packet of each TCP connection but not the SYN/ACK replies?',
                    options: [
                        'tcp.flags.syn == 1 && tcp.flags.ack == 0',
                        'tcp.flags.syn == 1',
                        'tcp.flags.ack == 0'
                    ],
                    answer: 0,
                    explain: 'An initial SYN has SYN set and ACK clear. Removing the ACK condition would also include SYN/ACK replies.'
                }
            },
            {
                challenge: true,
                text: 'Reason from the Client Hello',
                quiz: {
                    q: 'A Client Hello carries SNI shop.example.com but no HTTP request appears. What can you still conclude?',
                    options: [
                        'The client intended to reach shop.example.com over TLS',
                        'The client downloaded a Windows executable',
                        'The server refused the TCP connection'
                    ],
                    answer: 0,
                    explain: 'The SNI states the hostname the client wants. Encrypted application data can hide the HTTP request without hiding that intent.'
                }
            }
        ],
        ch4: [
            {
                challenge: true,
                text: 'Find the byte-heavy protocol',
                quiz: {
                    q: 'You need the protocol that moved the most bytes, not the most packets. Which view answers that fastest?',
                    options: [
                        'Statistics → Protocol Hierarchy',
                        'Statistics → IO Graph',
                        'View → Coloring Rules'
                    ],
                    answer: 0,
                    explain: 'Protocol Hierarchy reports both packet and byte totals per protocol, so sorting by bytes identifies the heavy protocol.'
                }
            },
            {
                challenge: true,
                text: 'Preserve while narrowing',
                quiz: {
                    q: 'Which workflow keeps evidence visible after you apply a narrow filter?',
                    options: [
                        'Mark the packets with Ctrl+M, then apply the filter',
                        'Delete the packets, then apply the filter',
                        'Open IO Graph and clear the series'
                    ],
                    answer: 0,
                    explain: 'Marks survive filter changes. Deleting or clearing views removes the evidence instead of preserving it.'
                }
            }
        ],
        ch5: [
            {
                challenge: true,
                text: 'Interpret the unreachable code',
                quiz: {
                    q: 'A UDP flow receives ICMP type 3 code 3. Which conclusion is correct?',
                    options: [
                        'The host is reachable but no service listens on that UDP port',
                        'The destination network does not exist',
                        'The TCP connection was refused'
                    ],
                    answer: 0,
                    explain: 'Type 3 code 3 is port unreachable. The host answered with ICMP, so it exists, but nothing is bound to that UDP port.'
                }
            },
            {
                challenge: true,
                text: 'Chain the TLS failure',
                quiz: {
                    q: 'A fatal TLS alert 40 is followed by a TCP RST. What is the best interpretation?',
                    options: [
                        'The handshake failed and the connection was torn down',
                        'The handshake succeeded and data began flowing',
                        'The client requested a larger receive window'
                    ],
                    answer: 0,
                    explain: 'Alert 40 is handshake_failure. The following reset ends the failed connection.'
                }
            }
        ],
        ch6: [
            {
                challenge: true,
                text: 'Name the recovery mechanism',
                quiz: {
                    q: 'A segment is missing, three duplicate ACKs arrive, and the retransmission follows 2 ms later. Which mechanism ran?',
                    options: [
                        'Fast retransmit',
                        'A timeout retransmit after the RTO expired',
                        'Slow start after an idle period'
                    ],
                    answer: 0,
                    explain: 'Three duplicate ACKs trigger fast retransmit immediately, well before a normal retransmission timeout would expire.'
                }
            },
            {
                challenge: true,
                text: 'Avoid duplicate delivery',
                quiz: {
                    q: 'Why does the receiver not deliver a retransmitted segment to the application twice?',
                    options: [
                        'It discards bytes it has already received in that sequence range',
                        'It closes the socket on the duplicate',
                        'It converts the duplicate into a DNS query'
                    ],
                    answer: 0,
                    explain: 'TCP tracks the next expected byte. A segment that covers an already-received range is discarded, so the application sees the data once.'
                }
            }
        ],
        ch7: [
            {
                challenge: true,
                text: 'Read the scan result',
                quiz: {
                    q: 'A host scans nine ports and one completes the TCP handshake. What does that tell you?',
                    options: [
                        'At least one scanned service is open',
                        'All nine ports are closed',
                        'The host is not scanning at all'
                    ],
                    answer: 0,
                    explain: 'A completed handshake means that port accepted the connection. The other eight answered with resets and are closed.'
                }
            },
            {
                challenge: true,
                text: 'Support the tunnel finding',
                quiz: {
                    q: 'Which two observations together support a DNS tunnel?',
                    options: [
                        'Long encoded labels and one shared parent domain',
                        'Short lookups for popular websites and many A records',
                        'Repeated PTR lookups for local addresses'
                    ],
                    answer: 0,
                    explain: 'Encoded labels carry the data and the shared parent domain groups the chunks into one channel.'
                }
            }
        ],
        ch8: [
            {
                challenge: true,
                text: 'Explain the multicast target',
                quiz: {
                    q: 'Why is a Neighbor Solicitation sent to ff02::1:ff00:1?',
                    options: [
                        'It is the solicited-node multicast address derived from the target',
                        'It is the all-routers broadcast address',
                        'It is the DNS server anycast address'
                    ],
                    answer: 0,
                    explain: 'IPv6 derives a solicited-node multicast address from the target address so only the relevant neighbours process the solicitation.'
                }
            },
            {
                challenge: true,
                text: 'Filter one AAAA lookup',
                quiz: {
                    q: 'Which filter isolates AAAA lookups for example.com?',
                    options: [
                        'dns.qry.type == 28 && dns.qry.name contains example.com',
                        'dns.qry.type == 1 && dns.qry.name contains example.com',
                        'ipv6.addr == example.com'
                    ],
                    answer: 0,
                    explain: 'AAAA is type 28. Combining it with the name keeps only the IPv6 lookup for that host.'
                }
            }
        ],
        ch9: [
            {
                challenge: true,
                text: 'Predict the next request',
                quiz: {
                    q: 'A 302 points to /account and sets a session cookie. Which request should appear next?',
                    options: [
                        'GET /account with the Cookie header',
                        'POST /login without any cookie',
                        'A DNS AAAA query for /account'
                    ],
                    answer: 0,
                    explain: 'The browser follows Location and returns the stored session cookie on the next request to that site.'
                }
            },
            {
                challenge: true,
                text: 'Read the Referer leak',
                quiz: {
                    q: 'A tracking pixel request has Host metrics.example.org and Referer shop.example.com. What does the Referer leak?',
                    options: [
                        'The page URL the user came from',
                        'The tracker API key',
                        'The server TLS certificate'
                    ],
                    answer: 0,
                    explain: 'Referer carries the source page URL, which tells the third-party tracker where the user was before the request.'
                }
            }
        ],
        ch10: [
            {
                challenge: true,
                text: 'Explain the missing Server Hello',
                quiz: {
                    q: 'Three Client Hellos appear but only two Server Hellos. What is the most likely explanation?',
                    options: [
                        'One handshake failed or received no server response',
                        'TLS 1.3 never sends Server Hellos',
                        'The capture lost all application data'
                    ],
                    answer: 0,
                    explain: 'Every accepted TLS 1.2 session answers with a Server Hello. A missing reply points to a failed or unanswered handshake.'
                }
            },
            {
                challenge: true,
                text: 'Decode the alert',
                quiz: {
                    q: 'A fatal TLS alert has description 70. What does it mean?',
                    options: [
                        'protocol_version',
                        'handshake_failure',
                        'bad_certificate'
                    ],
                    answer: 0,
                    explain: 'Alert 70 is protocol_version. Alert 40 is handshake_failure and 42 is bad_certificate.'
                }
            }
        ],
        ch11: [
            {
                challenge: true,
                text: 'Link the stages',
                quiz: {
                    q: 'The same WinHttp User-Agent appears on the download and the later gate POST. What does that link?',
                    options: [
                        'The same client tooling across two stages of the intrusion',
                        'Two unrelated users on the same network',
                        'The web server and the DNS resolver'
                    ],
                    answer: 0,
                    explain: 'A distinctive scripted-client string on both requests ties the download and the check-in to one implant.'
                }
            },
            {
                challenge: true,
                text: 'Pick the real domain',
                quiz: {
                    q: 'An NXDOMAIN burst is followed by one successful A record. Which name most likely belongs to the controller?',
                    options: [
                        'The one name that resolved successfully',
                        'Any of the failed random names',
                        'The name in the MZ header'
                    ],
                    answer: 0,
                    explain: 'DGA guesses mostly fail. The successful lookup is the infrastructure the implant can actually use.'
                }
            }
        ],
        ch12: [
            {
                challenge: true,
                text: 'Read the beacon timing',
                quiz: {
                    q: 'Beacons arrive at 60 s, 62 s, 59 s and 61 s. What does the variation suggest?',
                    options: [
                        'A jittered beacon interval',
                        'A failed DNS resolver',
                        'A user browsing manually'
                    ],
                    answer: 0,
                    explain: 'A tight interval with small random variation is jitter, used to make automated check-ins less predictable.'
                }
            },
            {
                challenge: true,
                text: 'Avoid a one-channel blind spot',
                quiz: {
                    q: 'HTTPS uses 443, the HTTP fallback uses 80, DNS uses 53 and ICMP has no ports. Which statement is true?',
                    options: [
                        'Filtering only port 443 would miss the fallback channels',
                        'Filtering only port 443 captures every channel',
                        'ICMP can be found with tcp.port == 443'
                    ],
                    answer: 0,
                    explain: 'The implant spreads across four channels. A port-443-only filter sees the beacons but not the HTTP, DNS or ICMP fallbacks.'
                }
            }
        ]
    };

    CHAPTERS.forEach(function (chapter) {
        var tasks = CHAPTER_CHALLENGES_2[chapter.id];
        if (!tasks || !chapter.missions.length) return;
        var capstone = chapter.missions[chapter.missions.length - 1];
        tasks.forEach(function (task) { capstone.tasks.push(task); });
    });

    var CHAPTER_CHALLENGES_3 = {
        'first-packet': [
            {
                challenge: true,
                text: 'Confirm an executable in the bytes',
                quiz: {
                    q: 'Which pane would you open to confirm a payload starts with the MZ signature?',
                    options: ['Packet list', 'Packet details', 'Packet bytes'],
                    answer: 2,
                    explain: 'The packet bytes pane shows the raw hex and ASCII, so the first bytes of a payload are visible there.'
                }
            },
            {
                challenge: true,
                text: 'Expand the protocol tree',
                quiz: {
                    q: 'Which pane lets you expand Ethernet, IP and TCP fields for one frame?',
                    options: ['Packet list', 'Packet details', 'Packet bytes'],
                    answer: 1,
                    explain: 'The packet details pane is the decoded protocol tree. Expanding a layer reveals its individual fields.'
                }
            }
        ],
        'read-columns': [
            {
                challenge: true,
                text: 'Understand the Time column',
                quiz: {
                    q: 'What is the Time column measured relative to by default?',
                    options: ['The start of the capture', 'The previous packet', 'The system boot time'],
                    answer: 0,
                    explain: 'The default Time column is seconds since the first captured frame. Wireshark can change that reference in the preferences.'
                }
            },
            {
                challenge: true,
                text: 'Narrow the frame list',
                quiz: {
                    q: 'Which action narrows the packet list to only frames that match a protocol or field?',
                    options: ['Select a row', 'Apply a display filter', 'Mark a packet'],
                    answer: 1,
                    explain: 'A display filter hides non-matching frames. Selecting and marking do not change which rows are shown.'
                }
            }
        ],
        'one-story': [
            {
                challenge: true,
                text: 'Order a complete web visit',
                quiz: {
                    q: 'Which sequence correctly describes this web session?',
                    options: [
                        'ARP, DNS, TCP handshake, HTTP request, HTTP response',
                        'DNS, ARP, HTTP request, TCP handshake, HTTP response',
                        'TCP handshake, DNS, HTTP response, ARP, HTTP request'
                    ],
                    answer: 0,
                    explain: 'The client finds the gateway with ARP, resolves the name with DNS, opens TCP, then sends and receives HTTP.'
                }
            }
        ],
        'ping-pong': [
            {
                challenge: true,
                text: 'Read the highest protocol',
                quiz: {
                    q: 'The Info column says "Echo (ping) request". Which protocol should the Protocol column show?',
                    options: ['TCP', 'ICMP', 'HTTP'],
                    answer: 1,
                    explain: 'Echo requests and replies are ICMP messages. They are not carried by TCP or HTTP.'
                }
            }
        ],
        'filter-protocol': [
            {
                challenge: true,
                text: 'Exclude one protocol',
                quiz: {
                    q: 'Which filter hides DNS while keeping every other protocol?',
                    options: ['!dns', 'dns', 'dns == 0'],
                    answer: 0,
                    explain: 'The ! operator inverts the term, so !dns matches everything that is not DNS. A bare dns would keep only DNS.'
                }
            },
            {
                challenge: true,
                text: 'Ask for either service',
                quiz: {
                    q: 'Which filter keeps both HTTP and TLS traffic?',
                    options: ['http && tls', 'http || tls', 'http ! tls'],
                    answer: 1,
                    explain: '|| is logical OR, so it keeps packets that match either protocol. && would require both in the same packet.'
                }
            }
        ],
        'filter-address': [
            {
                challenge: true,
                text: 'Follow traffic toward a port',
                quiz: {
                    q: 'Which filter shows packets heading to TCP port 443 from any host?',
                    options: ['tcp.port == 443', 'tcp.dstport == 443', 'tcp.srcport == 443'],
                    answer: 1,
                    explain: 'tcp.dstport matches only the destination port, so it shows traffic heading to the service. tcp.port matches either direction.'
                }
            }
        ],
        'filter-logic': [
            {
                challenge: true,
                text: 'Group the expression',
                quiz: {
                    q: 'Which filter means ARP or DNS traffic, but only when either endpoint is 10.0.0.1?',
                    options: [
                        '(arp || dns) && ip.addr == 10.0.0.1',
                        'arp || dns && ip.addr == 10.0.0.1',
                        'arp && dns || ip.addr == 10.0.0.1'
                    ],
                    answer: 0,
                    explain: 'Parentheses group the protocol choice before the && host condition, so the host rule applies to both ARP and DNS.'
                }
            },
            {
                challenge: true,
                text: 'Invalid filter behaviour',
                quiz: {
                    q: 'What happens when you type an invalid display filter?',
                    options: [
                        'The bar turns red and the previous result set stays',
                        'The capture is deleted',
                        'Wireshark closes the file'
                    ],
                    answer: 0,
                    explain: 'An invalid expression turns the filter bar red and does not replace the current results, so you can correct the syntax safely.'
                }
            }
        ],
        'filter-challenge': [
            {
                challenge: true,
                text: 'Search two name fields',
                quiz: {
                    q: 'Which filter finds a DNS name or an HTTP Host containing the word example?',
                    options: [
                        'dns.qry.name contains example || http.host contains example',
                        'dns.qry.name contains example && http.host contains example',
                        'dns.qry.name == example'
                    ],
                    answer: 0,
                    explain: 'The two fields live in different protocols. Using || lets either protocol match the substring example.'
                }
            }
        ],
        'dns-detail': [
            {
                challenge: true,
                text: 'Map a name to IPv4',
                quiz: {
                    q: 'Which DNS record type returns an IPv4 address?',
                    options: ['A', 'AAAA', 'MX'],
                    answer: 0,
                    explain: 'A returns an IPv4 address. AAAA returns IPv6 and MX names a mail server.'
                }
            },
            {
                challenge: true,
                text: 'Filter A queries',
                quiz: {
                    q: 'Which filter keeps only DNS A-record queries?',
                    options: ['dns.qry.type == 1', 'dns.qry.type == 28', 'dns.qry.type == 16'],
                    answer: 0,
                    explain: 'A is query type 1. Type 28 is AAAA and type 16 is TXT.'
                }
            }
        ],
        'tcp-handshake': [
            {
                challenge: true,
                text: 'Close a connection gracefully',
                quiz: {
                    q: 'Which TCP flag begins a graceful connection close?',
                    options: ['SYN', 'FIN', 'RST'],
                    answer: 1,
                    explain: 'FIN asks to close the connection gracefully. RST aborts it immediately and SYN opens a new one.'
                }
            },
            {
                challenge: true,
                text: 'Finish the handshake',
                quiz: {
                    q: 'Which packet does the client send last in the three-way handshake?',
                    options: ['A SYN', 'A SYN/ACK', 'An ACK'],
                    answer: 2,
                    explain: 'The client sends SYN, receives SYN/ACK and finishes with ACK. The SYN/ACK comes from the server.'
                }
            },
            {
                challenge: true,
                text: 'Identify the server side',
                quiz: {
                    q: 'In a captured TCP conversation, which side is normally the server?',
                    options: [
                        'The side using the well-known or listening port',
                        'The side with the higher frame number',
                        'The side that sends the most bytes'
                    ],
                    answer: 0,
                    explain: 'The server listens on a well-known port such as 80 or 443. The client usually uses an ephemeral source port.'
                }
            }
        ],
        'follow-stream': [
            {
                challenge: true,
                text: 'Find the certificate message',
                quiz: {
                    q: 'Which filter isolates TLS Certificate handshake messages?',
                    options: ['tls.handshake.type == 11', 'tls.handshake.type == 1', 'tls.handshake.type == 2'],
                    answer: 0,
                    explain: 'Type 11 is Certificate. Type 1 is Client Hello and type 2 is Server Hello.'
                }
            }
        ],
        'hierarchy': [
            {
                challenge: true,
                text: 'Complement the hierarchy',
                quiz: {
                    q: 'Which Statistics view aggregates traffic per host rather than per protocol?',
                    options: ['Endpoints', 'Protocol Hierarchy', 'IO Graph'],
                    answer: 0,
                    explain: 'Endpoints totals packets and bytes for each host. Protocol Hierarchy totals by protocol layer.'
                }
            }
        ],
        'conversations': [
            {
                challenge: true,
                text: 'Find the longest conversation',
                quiz: {
                    q: 'Which Conversations column identifies the longest-running conversation?',
                    options: ['Duration', 'Packets', 'Port'],
                    answer: 0,
                    explain: 'Duration reports how long each conversation lasted. Packets counts frames, not time.'
                }
            },
            {
                challenge: true,
                text: 'Separate pairs from hosts',
                quiz: {
                    q: 'What is the difference between Conversations and Endpoints?',
                    options: [
                        'Conversations groups address/port pairs; Endpoints aggregates per host',
                        'Conversations lists protocols; Endpoints lists frames',
                        'They show exactly the same data'
                    ],
                    answer: 0,
                    explain: 'A conversation is a pair of endpoints. Endpoints rolls traffic up by individual host address.'
                }
            }
        ],
        'io-graph': [
            {
                challenge: true,
                text: 'Choose the graph resolution',
                quiz: {
                    q: 'Which IO Graph setting controls how finely bursts are separated in time?',
                    options: ['The interval', 'The coloring rule', 'The capture filter'],
                    answer: 0,
                    explain: 'A small interval separates exchanges; a large interval merges them into one block. The interval controls time resolution.'
                }
            }
        ],
        'make-it-yours': [
            {
                challenge: true,
                text: 'Colour rows by filter',
                quiz: {
                    q: 'Which feature applies display filters to row colours?',
                    options: ['View → Coloring Rules', 'Statistics → Endpoints', 'Edit → Find Packet'],
                    answer: 0,
                    explain: 'Coloring Rules map display filters to row colours, so matching frames stand out in the list.'
                }
            },
            {
                challenge: true,
                text: 'Know custom column limits',
                quiz: {
                    q: 'You add a column for http.host. What does it show on a non-HTTP packet?',
                    options: ['Nothing — the field is blank', 'The IP address instead', 'The frame number'],
                    answer: 0,
                    explain: 'A custom field column only has a value when that field exists in the frame. Non-HTTP packets show a blank cell.'
                }
            }
        ],
        'nxdomain': [
            {
                challenge: true,
                text: 'Read a refused lookup',
                quiz: {
                    q: 'Which DNS RCODE value means the query was refused?',
                    options: ['0', '3', '5'],
                    answer: 2,
                    explain: 'RCODE 5 is REFUSED. RCODE 0 is success and 3 is NXDOMAIN.'
                }
            }
        ],
        'connection-refused': [
            {
                challenge: true,
                text: 'Filter every reset',
                quiz: {
                    q: 'Which filter finds every TCP reset?',
                    options: ['tcp.flags.rst == 1', 'tcp.flags.syn == 1', 'tcp.flags.fin == 1'],
                    answer: 0,
                    explain: 'tcp.flags.rst == 1 matches packets with the reset flag. SYN and FIN are different connection events.'
                }
            }
        ],
        'zero-window': [
            {
                challenge: true,
                text: 'Name the receive buffer field',
                quiz: {
                    q: 'Which TCP field advertises the receiver receive buffer space?',
                    options: ['Window size', 'Sequence number', 'Urgent pointer'],
                    answer: 0,
                    explain: 'The window size field tells the sender how much data the receiver can accept. Zero means stop sending.'
                }
            }
        ],
        'port-unreachable': [
            {
                challenge: true,
                text: 'Filter unreachable errors',
                quiz: {
                    q: 'Which filter keeps ICMP destination-unreachable messages?',
                    options: ['icmp.type == 3', 'icmp.type == 0', 'icmp.type == 8'],
                    answer: 0,
                    explain: 'ICMP type 3 is destination unreachable. Type 0 is echo reply and type 8 is echo request.'
                }
            }
        ],
        'tls-alert': [
            {
                challenge: true,
                text: 'Decode a certificate alert',
                quiz: {
                    q: 'Which TLS alert description means bad_certificate?',
                    options: ['42', '40', '70'],
                    answer: 0,
                    explain: 'Alert 42 is bad_certificate. Alert 40 is handshake_failure and 70 is protocol_version.'
                }
            }
        ],
        'case-file': [
            {
                challenge: true,
                text: 'Explain the silent request',
                quiz: {
                    q: 'A GET request appears but no response and no RST follow. What is the best explanation?',
                    options: [
                        'The server silently dropped the request or the response was lost',
                        'The TCP handshake never happened',
                        'The client sent a DNS query instead'
                    ],
                    answer: 0,
                    explain: 'A missing response without a reset can mean a firewall drop, a crashed service or a lost packet. The handshake already had to succeed for the GET to be sent.'
                }
            }
        ],
        'retransmission': [
            {
                challenge: true,
                text: 'Define the retransmission timeout',
                quiz: {
                    q: 'What does the retransmission timeout (RTO) estimate?',
                    options: [
                        'How long TCP waits for an ACK before resending',
                        'How long a DNS record stays cached',
                        'How many ports a scan can reach'
                    ],
                    answer: 0,
                    explain: 'The RTO is TCP estimate of the round-trip time plus margin. If no ACK arrives in that window, the segment is resent.'
                }
            }
        ],
        'dup-acks': [
            {
                challenge: true,
                text: 'Read a payload-free ACK',
                quiz: {
                    q: 'A packet has tcp.ack set, tcp.len == 0 and repeats the previous acknowledgment. What is it?',
                    options: [
                        'A duplicate ACK carrying no payload',
                        'A retransmitted HTTP response',
                        'A DNS query'
                    ],
                    answer: 0,
                    explain: 'No payload plus a repeated ACK number is a duplicate ACK. It signals that data after the acknowledged byte is missing.'
                }
            }
        ],
        'fragments': [
            {
                challenge: true,
                text: 'Identify the first fragment flags',
                quiz: {
                    q: 'Which flags identify the first fragment of an IPv4 datagram?',
                    options: [
                        'Fragment offset 0 with More Fragments set',
                        'Fragment offset greater than 0 with More Fragments set',
                        'Fragment offset 0 with More Fragments clear'
                    ],
                    answer: 0,
                    explain: 'The first fragment starts at offset 0 and has More Fragments set because later pieces follow.'
                }
            },
            {
                challenge: true,
                text: 'Filter the final fragment',
                quiz: {
                    q: 'Which filter finds the last fragment of a fragmented datagram?',
                    options: [
                        'ip.frag_offset > 0 && ip.flags.mf == 0',
                        'ip.frag_offset == 0 && ip.flags.mf == 1',
                        'ip.frag_offset > 0 && ip.flags.mf == 1'
                    ],
                    answer: 0,
                    explain: 'A later fragment has a non-zero offset. The last piece is the one that clears More Fragments.'
                }
            },
            {
                challenge: true,
                text: 'Filter the opening fragment',
                quiz: {
                    q: 'Which filter finds the first piece of a fragmented datagram?',
                    options: [
                        'ip.frag_offset == 0 && ip.flags.mf == 1',
                        'ip.frag_offset > 0 && ip.flags.mf == 1',
                        'ip.frag_offset > 0 && ip.flags.mf == 0'
                    ],
                    answer: 0,
                    explain: 'The first piece has offset 0 and More Fragments set. Requiring MF excludes ordinary unfragmented packets.'
                }
            }
        ],
        'slow-transfer': [
            {
                challenge: true,
                text: 'Explain the added delay',
                quiz: {
                    q: 'Why does a retransmission increase application latency even when the data eventually arrives?',
                    options: [
                        'The receiver waits for the missing sequence before delivering later bytes',
                        'The destination IP address changes',
                        'The application restarts the TCP handshake'
                    ],
                    answer: 0,
                    explain: 'TCP delivers bytes in order. Later data waits in the buffer until the missing segment is filled, so the application sees a stall.'
                }
            }
        ],
        'arp-spoof': [
            {
                challenge: true,
                text: 'Read the claimed mapping',
                quiz: {
                    q: 'Which ARP fields show the mapping a reply is claiming?',
                    options: [
                        'Sender IP and sender MAC',
                        'Target IP and target MAC',
                        'Source and destination TCP ports'
                    ],
                    answer: 0,
                    explain: 'The sender protocol address (IP) and sender hardware address (MAC) are the claimed binding. The target fields identify who should learn it.'
                }
            },
            {
                challenge: true,
                text: 'Filter ARP replies',
                quiz: {
                    q: 'Which filter keeps only ARP replies?',
                    options: ['arp.opcode == 2', 'arp.opcode == 1', 'arp.src.proto_ipv4 == 1'],
                    answer: 0,
                    explain: 'ARP opcode 1 is request and 2 is reply. Filtering opcode 2 isolates the answers that can poison a cache.'
                }
            }
        ],
        'port-scan': [
            {
                challenge: true,
                text: 'Name the handshake scan',
                quiz: {
                    q: 'Which scan type completes the full TCP handshake on open ports?',
                    options: ['TCP connect scan', 'SYN scan', 'UDP scan'],
                    answer: 0,
                    explain: 'A connect scan completes SYN, SYN/ACK and ACK. A SYN scan stops after the SYN/ACK to stay quieter.'
                }
            }
        ],
        'dns-tunnel': [
            {
                challenge: true,
                text: 'Explain the encoded labels',
                quiz: {
                    q: 'Why do long random-looking DNS labels matter in a tunnel investigation?',
                    options: [
                        'They can encode commands or stolen data',
                        'They speed up recursive lookups',
                        'They prove the domain is popular'
                    ],
                    answer: 0,
                    explain: 'Normal names are short and readable. Long high-entropy labels can carry base32 or hex-encoded payloads through DNS.'
                }
            }
        ],
        'malicious-upload': [
            {
                challenge: true,
                text: 'Filter the upload endpoint',
                quiz: {
                    q: 'Which filter finds POST requests to a PHP endpoint?',
                    options: [
                        'http.request.method == "POST" && http.request.uri contains ".php"',
                        'http.response.code == 200',
                        'tcp.dstport == 443'
                    ],
                    answer: 0,
                    explain: 'Combining the method with a URI substring keeps only POSTs to PHP scripts, the common upload pattern in this capture.'
                }
            }
        ],
        'c2-sni': [
            {
                challenge: true,
                text: 'Pivot after the upload',
                quiz: {
                    q: 'You found the upload POST. Which value is the best first pivot to later C2 traffic?',
                    options: [
                        'The destination IP address of the POST',
                        'The frame length of the POST',
                        'The client ephemeral source port'
                    ],
                    answer: 0,
                    explain: 'The server address is reused by later beaconing. The ephemeral source port is specific to one connection.'
                }
            }
        ],
        'v6-neighbours': [
            {
                challenge: true,
                text: 'Name the advertisement',
                quiz: {
                    q: 'Which ICMPv6 type is Neighbor Advertisement?',
                    options: ['136', '135', '134'],
                    answer: 0,
                    explain: 'Type 136 is Neighbor Advertisement. Type 135 is Neighbor Solicitation and 134 is Router Advertisement.'
                }
            },
            {
                challenge: true,
                text: 'Find all-nodes multicast',
                quiz: {
                    q: 'Which address is the IPv6 all-nodes multicast group?',
                    options: ['ff02::1', 'ff02::2', 'ff02::1:ff00:1'],
                    answer: 0,
                    explain: 'ff02::1 reaches all nodes on the link. ff02::2 reaches all routers, and ff02::1:ff00:1 is a solicited-node group.'
                }
            },
            {
                challenge: true,
                text: 'Justify multicast discovery',
                quiz: {
                    q: 'Why does IPv6 use multicast for Neighbor Discovery instead of broadcast?',
                    options: [
                        'It reaches only the nodes that need the message',
                        'It encrypts the neighbour messages',
                        'It removes the need for IP addresses'
                    ],
                    answer: 0,
                    explain: 'Solicited-node multicast targets the nodes likely to care, avoiding the cost of waking every host on the link.'
                }
            }
        ],
        'v6-router': [
            {
                challenge: true,
                text: 'Filter router advertisements',
                quiz: {
                    q: 'Which filter keeps only IPv6 Router Advertisements?',
                    options: ['icmpv6.type == 134', 'icmpv6.type == 133', 'icmpv6.type == 135'],
                    answer: 0,
                    explain: 'Type 134 is Router Advertisement. Type 133 is Router Solicitation and 135 is Neighbor Solicitation.'
                }
            }
        ],
        'v6-tls': [
            {
                challenge: true,
                text: 'Name the upper-layer field',
                quiz: {
                    q: 'Which IPv6 header field identifies the next header, such as TCP or ICMPv6?',
                    options: ['Next Header', 'Traffic Class', 'Payload Length'],
                    answer: 0,
                    explain: 'Next Header names the protocol that follows the IPv6 header. It plays the role of the IPv4 Protocol field.'
                }
            },
            {
                challenge: true,
                text: 'Filter ICMPv6 by next header',
                quiz: {
                    q: 'Which filter finds IPv6 packets whose next header is ICMPv6 (58)?',
                    options: ['ipv6.nxt == 58', 'ipv6.nxt == 6', 'ip.proto == 58'],
                    answer: 0,
                    explain: 'ipv6.nxt is the IPv6 Next Header field. 58 means ICMPv6; 6 means TCP.'
                }
            }
        ],
        'web-login': [
            {
                challenge: true,
                text: 'Ask for headers only',
                quiz: {
                    q: 'Which HTTP method requests headers without a response body?',
                    options: ['HEAD', 'GET', 'POST'],
                    answer: 0,
                    explain: 'HEAD returns the same headers as GET but no body. GET retrieves a body and POST submits data.'
                }
            }
        ],
        'web-redirect': [
            {
                challenge: true,
                text: 'Read unauthorized',
                quiz: {
                    q: 'Which HTTP status code means the request is unauthorized?',
                    options: ['401', '302', '404'],
                    answer: 0,
                    explain: '401 Unauthorized means authentication is required or failed. 302 is a redirect and 404 is not found.'
                }
            }
        ],
        'web-cookies': [
            {
                challenge: true,
                text: 'Filter the cookie setter',
                quiz: {
                    q: 'Which filter finds responses that set a session cookie?',
                    options: [
                        'http.set_cookie contains session',
                        'http.cookie contains session',
                        'http.referer contains session'
                    ],
                    answer: 0,
                    explain: 'http.set_cookie matches the Set-Cookie response header. http.cookie matches cookies sent by the client.'
                }
            },
            {
                challenge: true,
                text: 'Limit a cookie to HTTPS',
                quiz: {
                    q: 'Which cookie attribute keeps the browser from sending it over plain HTTP?',
                    options: ['Secure', 'HttpOnly', 'SameSite'],
                    answer: 0,
                    explain: 'Secure restricts the cookie to HTTPS. HttpOnly hides it from JavaScript and SameSite controls cross-site sending.'
                }
            }
        ],
        'web-tracking': [
            {
                challenge: true,
                text: 'Why a tiny image',
                quiz: {
                    q: 'Why is a tracking pixel often a tiny GIF?',
                    options: [
                        'It loads invisibly while still reporting the request',
                        'It encrypts the user session',
                        'It blocks third-party cookies'
                    ],
                    answer: 0,
                    explain: 'A one-pixel image is invisible on the page, but the request still tells the tracker the page, time and client details.'
                }
            }
        ],
        'web-download': [
            {
                challenge: true,
                text: 'Name the requested host',
                quiz: {
                    q: 'Which HTTP request header names the host the client wants to reach?',
                    options: ['Host', 'Referer', 'Content-Type'],
                    answer: 0,
                    explain: 'The Host header carries the requested hostname. Referer names the source page and Content-Type describes a body.'
                }
            }
        ],
        'tls-hellos': [
            {
                challenge: true,
                text: 'Identify application data',
                quiz: {
                    q: 'Which TLS content type carries encrypted application data?',
                    options: ['23', '22', '21'],
                    answer: 0,
                    explain: 'Content type 23 is Application Data. 22 is Handshake and 21 is Alert.'
                }
            }
        ],
        'tls-server-flight': [
            {
                challenge: true,
                text: 'Find the cipher choice',
                quiz: {
                    q: 'Which handshake message carries the server chosen cipher suite?',
                    options: ['Server Hello', 'Client Hello', 'Certificate'],
                    answer: 0,
                    explain: 'The Server Hello states the selected cipher suite and version. The Client Hello only offers candidates.'
                }
            },
            {
                challenge: true,
                text: 'Count the certificate type',
                quiz: {
                    q: 'Which TLS handshake type is Certificate?',
                    options: ['11', '2', '1'],
                    answer: 0,
                    explain: 'Type 11 is Certificate. Type 2 is Server Hello and type 1 is Client Hello.'
                }
            }
        ],
        'tls-alert-case': [
            {
                challenge: true,
                text: 'Identify a certificate failure',
                quiz: {
                    q: 'A fatal alert arrives because the peer rejected the certificate. Which description value is it?',
                    options: ['42', '40', '70'],
                    answer: 0,
                    explain: 'Alert 42 is bad_certificate. Alert 40 is handshake_failure and 70 is protocol_version.'
                }
            }
        ],
        'tls-legacy': [
            {
                challenge: true,
                text: 'Identify TLS 1.3',
                quiz: {
                    q: 'Which TLS record version is TLS 1.3?',
                    options: ['0x0304', '0x0303', '0x0301'],
                    answer: 0,
                    explain: '0x0304 is TLS 1.3. 0x0303 is TLS 1.2 and 0x0301 is TLS 1.0.'
                }
            }
        ],
        'tls-case': [
            {
                challenge: true,
                text: 'Filter Server Hellos',
                quiz: {
                    q: 'Which filter keeps only TLS Server Hellos?',
                    options: ['tls.handshake.type == 2', 'tls.handshake.type == 1', 'tls.handshake.type == 11'],
                    answer: 0,
                    explain: 'Type 2 is Server Hello. Type 1 is Client Hello and 11 is Certificate.'
                }
            }
        ],
        'mal-payload': [
            {
                challenge: true,
                text: 'Filter by saved filename',
                quiz: {
                    q: 'Which filter finds a download whose suggested filename contains update?',
                    options: [
                        'http.content_disposition contains update',
                        'http.host contains update',
                        'http.request.uri contains update'
                    ],
                    answer: 0,
                    explain: 'Content-Disposition carries the suggested filename. The URI and Host fields describe the request, not the saved name.'
                }
            }
        ],
        'mal-gate': [
            {
                challenge: true,
                text: 'Filter the gate path',
                quiz: {
                    q: 'Which filter finds the gate script by URI?',
                    options: [
                        'http.request.uri contains gate',
                        'http.response.code == 200',
                        'tcp.port == 80'
                    ],
                    answer: 0,
                    explain: 'The URI field contains the requested path. Matching gate isolates the check-in endpoint.'
                }
            },
            {
                challenge: true,
                text: 'Name the requested host',
                quiz: {
                    q: 'Which HTTP header identifies the server hostname in the gate request?',
                    options: ['Host', 'User-Agent', 'Cookie'],
                    answer: 0,
                    explain: 'Host carries the requested server name. User-Agent identifies the client and Cookie carries stored state.'
                }
            }
        ],
        'mal-exfil': [
            {
                challenge: true,
                text: 'Name the exfiltration port',
                quiz: {
                    q: 'Which service port do the DNS exfiltration queries use?',
                    options: ['53', '80', '443'],
                    answer: 0,
                    explain: 'DNS uses port 53, normally over UDP. The exfiltration hides inside ordinary-looking DNS queries.'
                }
            }
        ],
        'mal-beacon': [
            {
                challenge: true,
                text: 'Identify the next stage',
                quiz: {
                    q: 'Which stage follows the executable download in this malware chain?',
                    options: ['A TLS beacon to the controller', 'A DNS NXDOMAIN burst', 'An ARP reply'],
                    answer: 0,
                    explain: 'After delivery, the implant beacons over TLS. The DGA failures came before the download in this capture.'
                }
            }
        ],
        'mal-case': [
            {
                challenge: true,
                text: 'Separate delivery from control',
                quiz: {
                    q: 'Why compare the download host with the beacon SNI?',
                    options: [
                        'They may be separate delivery and C2 infrastructure',
                        'They must always be the same server',
                        'It proves the file is not executable'
                    ],
                    answer: 0,
                    explain: 'Attackers often serve the payload from one host and control the implant from another. Comparing both maps the full infrastructure.'
                }
            }
        ],
        'c2-heartbeat': [
            {
                challenge: true,
                text: 'Find the beacon port',
                quiz: {
                    q: 'Which destination port do the HTTPS beacons use?',
                    options: ['443', '80', '53'],
                    answer: 0,
                    explain: 'The beacons use TLS on port 443. The fallback channel uses 80 and the tunnel uses 53.'
                }
            }
        ],
        'c2-dns': [
            {
                challenge: true,
                text: 'Find the tunnel port',
                quiz: {
                    q: 'Which port carries the DNS tunnel queries?',
                    options: ['53', '443', '80'],
                    answer: 0,
                    explain: 'DNS queries and responses use port 53. The tunnel hides its chunks inside those lookups.'
                }
            }
        ],
        'c2-http': [
            {
                challenge: true,
                text: 'Filter the fallback endpoint',
                quiz: {
                    q: 'Which filter finds the HTTP fallback check-in by URI?',
                    options: [
                        'http.request.uri contains checkin',
                        'http.request.uri contains beacon',
                        'http.host == "beacon.c2.example"'
                    ],
                    answer: 0,
                    explain: 'The fallback uses the checkin path. beacon.c2.example is the HTTPS SNI, not the HTTP fallback host.'
                }
            }
        ],
        'c2-icmp': [
            {
                challenge: true,
                text: 'Explain the portless channel',
                quiz: {
                    q: 'Why can ICMP be useful for a covert channel?',
                    options: [
                        'It has no ports and is often allowed through firewalls',
                        'It encrypts every payload with TLS',
                        'It always uses port 53'
                    ],
                    answer: 0,
                    explain: 'ICMP has no port numbers, so port-based rules may not block it. It can also blend in with ordinary ping traffic.'
                }
            },
            {
                challenge: true,
                text: 'Filter echo replies',
                quiz: {
                    q: 'Which filter keeps ICMP echo replies?',
                    options: ['icmp.type == 0', 'icmp.type == 8', 'icmp.type == 3'],
                    answer: 0,
                    explain: 'Type 0 is echo reply and type 8 is echo request. Type 3 is destination unreachable.'
                }
            }
        ],
        'c2-jitter': [
            {
                challenge: true,
                text: 'Combine timing and volume',
                quiz: {
                    q: 'Which two Statistics views together best show beacon timing and per-pair volume?',
                    options: [
                        'IO Graph and Conversations',
                        'Protocol Hierarchy and Coloring Rules',
                        'Endpoints and Column Preferences'
                    ],
                    answer: 0,
                    explain: 'IO Graph reveals the timing pattern and Conversations reports how much data each pair exchanged.'
                }
            }
        ]
    };

    CHAPTERS.forEach(function (chapter) {
        chapter.missions.forEach(function (mission) {
            var tasks = CHAPTER_CHALLENGES_3[mission.id];
            if (!tasks) return;
            tasks.forEach(function (task) { mission.tasks.push(task); });
        });
    });

    var EXTRA_MISSIONS_2 = {
        ch1: [
            {
                id: 'dns-pair',
                title: 'Pair the DNS messages',
                xp: 130,
                brief: 'A query and its answer share more than a name. The transaction ID is the thread that ties them together.',
                learn: 'DNS uses a 16-bit transaction ID so a resolver can match each reply to the right query. In this capture the A lookup uses 0x1a2b. Filtering on `dns.id` keeps the query and its answer while hiding unrelated lookups.',
                hints: [
                    'The A query is #3 and its answer is #4.',
                    'Filter dns.id == 0x1a2b to show exactly the pair.'
                ],
                tasks: [
                    { text: 'Select the DNS query (#3)', select: { no: 3 } },
                    { text: 'Show the matched DNS pair (dns.id == 0x1a2b)', filter: { expr: ['dns.id == 0x1a2b'], matches: 2 } },
                    { text: 'Select the DNS answer (#4)', select: { no: 4 } },
                    {
                        text: 'Name the pairing field',
                        quiz: {
                            q: 'Which DNS field pairs a query with its response?',
                            options: ['Transaction ID', 'Destination port', 'IP Identification'],
                            answer: 0,
                            explain: 'The transaction ID is copied from query to response. Port 53 is shared by every DNS packet and IP Identification belongs to the IP layer.'
                        }
                    },
                    {
                        text: 'Identify the answer',
                        quiz: {
                            q: 'Which packet is the DNS response for example.com?',
                            options: ['#3, the standard query', '#4, the standard query response', '#8, the HTTP request'],
                            answer: 1,
                            explain: 'Packet #4 is the response and carries the A record 203.0.113.10. Packet #3 asks the question.'
                        }
                    }
                ]
            }
        ],
        ch2: [
            {
                id: 'mixed-filter',
                title: 'Mix address and protocol',
                xp: 150,
                brief: 'An address filter can be narrowed to one protocol without losing the host condition. Learn to stack terms in the right order.',
                learn: '`&&` binds two conditions and `!` inverts a term. `ip.addr == 203.0.113.10 && tcp` keeps only TCP packets for that host, while replacing `tcp` with `!tcp` leaves the ICMP exchange. This is how analysts remove a noisy protocol without dropping the host of interest.',
                hints: [
                    'The server address is 203.0.113.10. Add && tcp to keep its TCP traffic.',
                    'Use !tcp to see only the ICMP packets for that server.'
                ],
                tasks: [
                    { text: 'Show TCP traffic for 203.0.113.10', filter: { expr: ['ip.addr == 203.0.113.10 && tcp'], matches: 10 } },
                    { text: 'Show non-TCP traffic for the same host', filter: { expr: ['ip.addr == 203.0.113.10 && !tcp'], matches: 2 } },
                    { text: 'Select the ICMP request (#12)', select: { no: 12 } },
                    {
                        text: 'Read the combination',
                        quiz: {
                            q: 'Which packets does ip.addr == 203.0.113.10 && !tcp keep?',
                            options: ['The ICMP request and reply', 'Every TCP packet to the server', 'Only the DNS response'],
                            answer: 0,
                            explain: 'The address condition keeps packets involving the server, and !tcp removes TCP. The two ICMP packets are what remain.'
                        }
                    },
                    {
                        text: 'Choose the operator',
                        quiz: {
                            q: 'Which operator narrows a result to the host and the protocol at the same time?',
                            options: ['&&', '||', '!'],
                            answer: 0,
                            explain: '&& is logical AND. || accepts either side and ! negates a single term.'
                        }
                    }
                ]
            }
        ],
        ch3: [
            {
                id: 'record-types',
                title: 'A and AAAA side by side',
                xp: 160,
                brief: 'One name can return both an IPv4 and an IPv6 address. Compare the two record types without leaving the same capture.',
                learn: 'DNS type 1 is an A record and returns an IPv4 address. Type 28 is AAAA and returns an IPv6 address. Filtering on `dns.qry.type` separates the two families, even when both queries ask for the same hostname.',
                hints: [
                    'The A lookup covers #3 and #4, while the AAAA lookup covers #5 and #6.',
                    'Filter dns.qry.type == 28 to isolate the AAAA pair.'
                ],
                tasks: [
                    { text: 'Show the A records (dns.qry.type == 1)', filter: { expr: ['dns.qry.type == 1'], matches: 4 } },
                    { text: 'Show the AAAA records (dns.qry.type == 28)', filter: { expr: ['dns.qry.type == 28'], matches: 2 } },
                    { text: 'Select the AAAA answer (#6)', select: { no: 6 } },
                    {
                        text: 'Compare the answers',
                        quiz: {
                            q: 'Which address does the AAAA answer return?',
                            options: ['203.0.113.50', '2001:db8::50', '198.51.100.20'],
                            answer: 1,
                            explain: 'The AAAA response carries the IPv6 address 2001:db8::50. The IPv4 address 203.0.113.50 came from the A record.'
                        }
                    },
                    {
                        text: 'Count the AAAA packets',
                        quiz: {
                            q: 'How many AAAA packets are in this capture?',
                            options: ['1', '2', '4'],
                            answer: 1,
                            explain: 'One AAAA query and one AAAA response make two packets. The four A packets cover two separate IPv4 lookups.'
                        }
                    }
                ]
            }
        ],
        ch4: [
            {
                id: 'http-objects',
                title: 'Extract the object',
                xp: 140,
                brief: 'Wireshark can pull files straight out of an HTTP conversation. Find the response that carries the logo and see what can be exported.',
                learn: 'The HTTP Objects dialog lists bodies Wireshark can reconstruct, such as images and documents. Filtering `http.response.code == 200` first shows successful transfers, and the Content-Type plus filename identify what the object is.',
                hints: [
                    'Open File → Export Objects → HTTP, or the HTTP Objects entry in the tools menu.',
                    'The logo response is #23 with Content-Type image/png.'
                ],
                tasks: [
                    { text: 'Open the HTTP Objects dialog', dialog: ['HTTP Objects'] },
                    { text: 'Show successful HTTP responses (http.response.code == 200)', filter: { expr: ['http.response.code == 200'], matches: 1 } },
                    { text: 'Select the logo response (#23)', select: { no: 23 } },
                    {
                        text: 'Name the exportable file',
                        quiz: {
                            q: 'Which file can be exported from this HTTP conversation?',
                            options: ['logo.png', 'index.html', 'stage2.exe'],
                            answer: 0,
                            explain: 'The only successful HTTP response in this capture is the PNG logo. There is no HTML page or executable download here.'
                        }
                    },
                    {
                        text: 'Find the feature',
                        quiz: {
                            q: 'Which dialog extracts bodies from HTTP traffic?',
                            options: ['HTTP Objects', 'Protocol Hierarchy', 'IO Graph'],
                            answer: 0,
                            explain: 'HTTP Objects reconstructs response bodies so they can be saved. The hierarchy and IO Graph only summarise traffic.'
                        }
                    }
                ]
            }
        ],
        ch5: [
            {
                id: 'reset-vs-unreachable',
                title: 'Reset or unreachable?',
                xp: 170,
                brief: 'Two failures look similar in a summary column but come from different layers. Compare a TCP reset with an ICMP unreachable.',
                learn: 'A TCP RST comes from the endpoint and aborts the connection. ICMP type 3 comes from a router or host and reports that a packet could not be delivered; code 3 specifically means the UDP port was unreachable. Reading the layer prevents you from blaming the wrong system.',
                hints: [
                    'The TCP refusal is #6 and the ICMP error is #13.',
                    'Filter tcp.flags.rst == 1, then icmp.type == 3.'
                ],
                tasks: [
                    { text: 'Show the TCP reset (tcp.flags.rst == 1)', filter: { expr: ['tcp.flags.rst == 1'], matches: 1 } },
                    { text: 'Select the RST/ACK (#6)', select: { no: 6 } },
                    { text: 'Show the ICMP unreachable (icmp.type == 3)', filter: { expr: ['icmp.type == 3'], matches: 1 } },
                    { text: 'Select the ICMP error (#13)', select: { no: 13 } },
                    {
                        text: 'Tell the failures apart',
                        quiz: {
                            q: 'Which failure means no service is listening on a UDP port?',
                            options: ['ICMP port unreachable', 'A TCP RST/ACK', 'A DNS NXDOMAIN'],
                            answer: 0,
                            explain: 'ICMP type 3 code 3 reports an unreachable UDP port. A TCP reset applies to TCP, and NXDOMAIN means the name does not exist.'
                        }
                    },
                    {
                        text: 'Find the abort',
                        quiz: {
                            q: 'Which packet aborts the TCP connection attempt?',
                            options: ['#5, the SYN', '#6, the RST/ACK', '#13, the ICMP error'],
                            answer: 1,
                            explain: 'Packet #6 resets the attempt to port 443. Packet #5 opens it and #13 belongs to a separate UDP lookup.'
                        }
                    }
                ]
            }
        ],
        ch6: [
            {
                id: 'payload-or-ack',
                title: 'Payload or pure ACK',
                xp: 200,
                brief: 'Not every TCP packet carries data. Separate the segments with a payload from the acknowledgements that only manage the conversation.',
                learn: '`tcp.len` reports the payload length. A pure ACK has `tcp.len == 0`, while a segment carrying an HTTP request or response has a positive length. Duplicate ACKs are pure ACKs that repeat the same acknowledgement number, which is why the length test is a useful first cut.',
                hints: [
                    'Four packets carry data: #8, #10, #11 and #16.',
                    'Filter tcp.len == 0 to see the twelve acknowledgement-only packets.'
                ],
                tasks: [
                    { text: 'Show packets with payload (tcp.len > 0)', filter: { expr: ['tcp.len > 0'], matches: 4 } },
                    { text: 'Show acknowledgement-only packets (tcp.len == 0)', filter: { expr: ['tcp.len == 0'], matches: 12 } },
                    { text: 'Select the retransmitted GET (#11)', select: { no: 11 } },
                    {
                        text: 'Identify the payload',
                        quiz: {
                            q: 'Which selected packet carries application data?',
                            options: ['#9, a pure ACK', '#11, the retransmitted GET', '#12, an ACK'],
                            answer: 1,
                            explain: 'Packet #11 repeats the HTTP request and has a positive TCP length. Packets #9 and #12 only acknowledge bytes.'
                        }
                    },
                    {
                        text: 'Define a pure ACK',
                        quiz: {
                            q: 'What distinguishes a pure ACK from a data segment?',
                            options: ['It carries no TCP payload', 'It uses a different IP address', 'It has no sequence number'],
                            answer: 0,
                            explain: 'A pure ACK has tcp.len == 0. It still carries sequence and acknowledgement numbers; it simply has no application bytes.'
                        }
                    }
                ]
            }
        ],
        ch7: [
            {
                id: 'decode-tunnel',
                title: 'Decode the tunnel label',
                xp: 210,
                brief: 'The DNS tunnel hides readable text inside base64 labels. Decode one label and prove what is moving through the resolver.',
                learn: 'Base64 turns arbitrary bytes into letters, digits and a small set of symbols, which makes it safe inside a DNS label. `aGVsbG8` decodes to the word hello. Long, high-entropy labels under one parent domain are a classic sign of DNS tunnelling or exfiltration.',
                hints: [
                    'The first TXT query is #22 with the label aGVsbG8.evil.example.',
                    'Base64 aGVsbG8 decodes to hello. The second label c2VjcmV0 decodes to secret.'
                ],
                tasks: [
                    { text: 'Show the first tunnel label (dns.qry.name contains aGVsbG8)', filter: { expr: ['dns.qry.name contains aGVsbG8'], matches: 2 } },
                    { text: 'Select the encoded query (#22)', select: { no: 22 } },
                    {
                        text: 'Decode the label',
                        quiz: {
                            q: 'What does the base64 label aGVsbG8 decode to?',
                            options: ['hello', 'secret', 'gateway'],
                            answer: 0,
                            explain: 'aGVsbG8 is the base64 encoding of hello. The next label, c2VjcmV0, decodes to secret.'
                        }
                    },
                    {
                        text: 'Explain the technique',
                        quiz: {
                            q: 'Why would an attacker encode data inside DNS labels?',
                            options: ['To pass data through controls that allow DNS', 'To make the resolver faster', 'To encrypt the IP header'],
                            answer: 0,
                            explain: 'DNS is often permitted, so encoding payloads in labels creates a covert channel that looks like ordinary lookups.'
                        }
                    }
                ]
            }
        ],
        ch8: [
            {
                id: 'neighbour-types',
                title: 'Solicit and advertise',
                xp: 210,
                brief: 'IPv6 neighbour discovery replaces ARP with two ICMPv6 messages. Tell the question from the answer.',
                learn: 'ICMPv6 type 135 is a Neighbor Solicitation and type 136 is a Neighbor Advertisement. The solicitation is sent to a solicited-node multicast address derived from the target, so only nearby hosts that care need to process it.',
                hints: [
                    'The solicitation is #3 and the advertisement is #4.',
                    'Filter icmpv6.type == 135, then icmpv6.type == 136.'
                ],
                tasks: [
                    { text: 'Show Neighbor Solicitations (icmpv6.type == 135)', filter: { expr: ['icmpv6.type == 135'], matches: 1 } },
                    { text: 'Select the solicitation (#3)', select: { no: 3 } },
                    { text: 'Show Neighbor Advertisements (icmpv6.type == 136)', filter: { expr: ['icmpv6.type == 136'], matches: 1 } },
                    { text: 'Select the advertisement (#4)', select: { no: 4 } },
                    {
                        text: 'Name the solicitation',
                        quiz: {
                            q: 'Which ICMPv6 type is a Neighbor Solicitation?',
                            options: ['135', '136', '134'],
                            answer: 0,
                            explain: 'Type 135 asks for a neighbour address. Type 136 answers it and type 134 is a Router Advertisement.'
                        }
                    },
                    {
                        text: 'Find the multicast target',
                        quiz: {
                            q: 'Which address receives the Neighbor Solicitation?',
                            options: ['ff02::1:ff00:1', 'ff02::1', 'ff02::2'],
                            answer: 0,
                            explain: 'The solicitation targets the solicited-node multicast group ff02::1:ff00:1. ff02::1 is all nodes and ff02::2 is all routers.'
                        }
                    }
                ]
            }
        ],
        ch9: [
            {
                id: 'request-paths',
                title: 'Request paths and results',
                xp: 220,
                brief: 'The URI in a request predicts the response that follows. Match two paths to their outcomes without reading the whole body.',
                learn: '`http.request.uri` matches the path portion of a request. A request for /download fetches the binary, while /missing produces a 404. Pairing the request URI with the following response code is a quick way to audit a web session.',
                hints: [
                    'The download request is #30 and the missing-page request is #34.',
                    'Filter http.request.uri contains download, then http.request.uri contains missing.'
                ],
                tasks: [
                    { text: 'Show the download request (http.request.uri contains download)', filter: { expr: ['http.request.uri contains download'], matches: 1 } },
                    { text: 'Select the download request (#30)', select: { no: 30 } },
                    { text: 'Show the missing-page request (http.request.uri contains missing)', filter: { expr: ['http.request.uri contains missing'], matches: 1 } },
                    { text: 'Select the missing-page request (#34)', select: { no: 34 } },
                    {
                        text: 'Match path to result',
                        quiz: {
                            q: 'Which request path returned a 404 response?',
                            options: ['/download', '/missing', '/account'],
                            answer: 1,
                            explain: 'The GET /missing request at #34 is answered with 404 Not Found. /download succeeds and /account loads after the redirect.'
                        }
                    },
                    {
                        text: 'Find the binary fetch',
                        quiz: {
                            q: 'Which request fetched the binary download?',
                            options: ['GET /download', 'GET /missing', 'POST /login'],
                            answer: 0,
                            explain: 'The GET /download request at #30 receives the octet-stream response. /missing fails and /login is the earlier form submission.'
                        }
                    }
                ]
            }
        ],
        ch10: [
            {
                id: 'certificates',
                title: 'Inspect the certificates',
                xp: 250,
                brief: 'Each successful TLS 1.2 handshake sends a certificate. Count them and see which session differs.',
                learn: 'The Certificate handshake message is type 11. A TLS 1.2 server sends it after the Server Hello, while TLS 1.3 encrypts it inside the handshake. Comparing the three sessions shows two successful certificate exchanges and one failure before a certificate could be used.',
                hints: [
                    'The certificate messages are #12, #22 and #32.',
                    'The failed session at #23 never completes the handshake.'
                ],
                tasks: [
                    { text: 'Show TLS Certificate messages (tls.handshake.type == 11)', filter: { expr: ['tls.handshake.type == 11'], matches: 3 } },
                    { text: 'Select the first certificate (#12)', select: { no: 12 } },
                    { text: 'Select the certificate in the rejected session (#22)', select: { no: 22 } },
                    {
                        text: 'Name the certificate message',
                        quiz: {
                            q: 'Which handshake message carries the server certificate?',
                            options: ['Certificate', 'Client Hello', 'Server Hello'],
                            answer: 0,
                            explain: 'The Certificate message carries the certificate chain. Client Hello and Server Hello negotiate the session but do not deliver the certificate.'
                        }
                    },
                    {
                        text: 'Count the certificates',
                        quiz: {
                            q: 'How many Certificate messages appear in this capture?',
                            options: ['2', '3', '4'],
                            answer: 1,
                            explain: 'Three servers send a certificate: telemetry, the rejected updates host and the CDN. The failed session still sends its certificate before the alert.'
                        }
                    }
                ]
            }
        ],
        ch11: [
            {
                id: 'ports-chain',
                title: 'Ports across the chain',
                xp: 260,
                brief: 'The infection uses port 80 for delivery and the gate, then port 443 for the beacon. Map each stage to its service port.',
                learn: 'Port 80 carries the payload download and the gate POST, while port 443 carries the TLS beacon. Seeing the same host spread across several service ports helps separate delivery, check-in and control even when the domains differ.',
                hints: [
                    'The payload and gate conversations use port 80.',
                    'The beacon to api.sync-telemetry.xyz uses port 443.'
                ],
                tasks: [
                    { text: 'Show port 80 traffic across the chain (tcp.port == 80)', filter: { expr: ['tcp.port == 80'], matches: 20 } },
                    { text: 'Select the payload download (#8)', select: { no: 8 } },
                    { text: 'Show port 443 beacon traffic (tcp.port == 443)', filter: { expr: ['tcp.port == 443'], matches: 10 } },
                    { text: 'Select the beacon Client Hello (#20)', select: { no: 20 } },
                    {
                        text: 'Map the beacon port',
                        quiz: {
                            q: 'Which service port carries the TLS beacon?',
                            options: ['80', '443', '53'],
                            answer: 1,
                            explain: 'The beacon to api.sync-telemetry.xyz uses TLS on port 443. Port 80 serves the download and gate, and 53 carries DNS exfiltration.'
                        }
                    },
                    {
                        text: 'Map the delivery port',
                        quiz: {
                            q: 'Which stage uses port 80 in this capture?',
                            options: ['The payload download and the gate POST', 'The TLS beacon only', 'The DNS exfiltration only'],
                            answer: 0,
                            explain: 'Both the stage2.exe download and the gate.php check-in use plain HTTP on port 80. The beacon uses 443 and exfiltration uses 53.'
                        }
                    }
                ]
            }
        ],
        ch12: [
            {
                id: 'fallback-survives',
                title: 'When HTTPS is blocked',
                xp: 270,
                brief: 'Blocking port 443 does not silence this implant. Follow the fallback channels that keep the check-in alive.',
                learn: 'The implant uses HTTPS on 443, an HTTP check-in on 80, DNS TXT chunks on 53 and ICMP keepalives with no ports. A firewall rule for one port leaves the others reachable, so an analyst must inventory every channel before declaring containment.',
                hints: [
                    'The HTTP fallback is #17 and the DNS chunks start at #24.',
                    'Filter http.request.uri contains checkin, then dns.qry.type == 16.'
                ],
                tasks: [
                    { text: 'Show the HTTP fallback (http.request.uri contains checkin)', filter: { expr: ['http.request.uri contains checkin'], matches: 1 } },
                    { text: 'Select the fallback request (#17)', select: { no: 17 } },
                    { text: 'Show the DNS tunnel (dns.qry.type == 16)', filter: { expr: ['dns.qry.type == 16'], matches: 8 } },
                    { text: 'Select the first tunnel chunk (#24)', select: { no: 24 } },
                    {
                        text: 'Choose the surviving channels',
                        quiz: {
                            q: 'Which channels survive a block on port 443?',
                            options: ['The HTTP, DNS and ICMP fallbacks', 'Only the HTTPS beacons', 'No channel survives'],
                            answer: 0,
                            explain: 'The HTTP check-in uses 80, DNS uses 53 and ICMP has no ports. Blocking only 443 leaves all three fallback channels reachable.'
                        }
                    },
                    {
                        text: 'Name the fallback port',
                        quiz: {
                            q: 'Which service port does the HTTP fallback use?',
                            options: ['53', '80', '443'],
                            answer: 1,
                            explain: 'The /api/v1/checkin request runs over HTTP on port 80. DNS uses 53 and the primary beacon uses 443.'
                        }
                    }
                ]
            }
        ]
    };

    CHAPTERS.forEach(function (chapter) {
        var extra = EXTRA_MISSIONS_2[chapter.id];
        if (!extra || !chapter.missions.length) return;
        chapter.missions.splice.apply(chapter.missions, [chapter.missions.length - 1, 0].concat(extra));
    });

    // One fill-in-the-blank check per mission. Answers are compared
    // case-insensitively, ignoring spaces and surrounding quotes.
    var FILL_BLANKS = {
        'first-packet': {
            q: 'The pane that shows raw hex and ASCII is the Packet ______ pane.',
            answer: 'bytes',
            accept: ['byte', 'packet bytes'],
            explain: 'The packet bytes pane shows the selected frame as hex on the left and ASCII on the right.'
        },
        'read-columns': {
            q: 'The Length column reports the size of a frame in ______.',
            answer: 'bytes',
            accept: ['byte'],
            explain: 'Length is the captured frame size in bytes. It is not the payload length or the packet count.'
        },
        'one-story': {
            q: 'Before a TCP connection starts, DNS resolves the name to an ______ address.',
            answer: 'IP',
            accept: ['ipv4', 'ip address'],
            explain: 'DNS returns the address the client needs before it can open a TCP connection to the server.'
        },
        'teardown': {
            q: 'A graceful TCP close begins with the ______ flag.',
            answer: 'FIN',
            accept: ['fin flag'],
            explain: 'Each side sends a FIN to signal that it has finished sending, then the final ACK completes the teardown.'
        },
        'dns-pair': {
            q: 'DNS matches a response to its query with the transaction ______.',
            answer: 'ID',
            accept: ['identifier'],
            explain: 'The 16-bit transaction ID is copied from the query into the response so the resolver can pair them.'
        },
        'ping-pong': {
            q: 'Ping uses an ICMP echo request and an echo ______.',
            answer: 'reply',
            accept: ['response'],
            explain: 'The echo reply carries the same identifier and sequence number as the request, which is how the pair is matched.'
        },

        'filter-protocol': {
            q: 'Only ARP packets match the display filter ______.',
            answer: 'arp',
            explain: 'A bare protocol name is a valid display filter. Typing arp hides every frame that is not ARP.'
        },
        'filter-address': {
            q: 'To match one host in either direction, use ______ == 10.0.0.1.',
            answer: 'ip.addr',
            accept: ['ip.addr==10.0.0.1'],
            explain: 'ip.addr matches the address whether it appears as the source or the destination.'
        },
        'filter-logic': {
            q: 'The ______ operator means either side can be true.',
            answer: '||',
            accept: ['or'],
            explain: '|| is logical OR. && requires both sides and ! negates a single term.'
        },
        'filter-challenge': {
            q: 'dns.flags.response == ______ finds DNS responses.',
            answer: '1',
            explain: 'The response bit is 1 on replies and 0 on queries, so the comparison keeps only replies.'
        },
        'filter-size': {
            q: 'tcp.srcport == 80 selects packets sent by the web ______.',
            answer: 'server',
            explain: 'Port 80 is the service port, so packets with source port 80 come from the server.'
        },
        'mixed-filter': {
            q: 'The ______ operator requires both conditions to be true.',
            answer: '&&',
            accept: ['and'],
            explain: '&& is logical AND. Both the address test and the protocol test must pass for a frame to stay visible.'
        },
        'port-story': {
            q: 'HTTPS normally uses TCP port ______.',
            answer: '443',
            explain: 'Port 443 is the default for HTTPS, while plain HTTP uses port 80.'
        },

        'dns-detail': {
            q: 'The DNS record type that returns an alias is ______.',
            answer: 'CNAME',
            accept: ['cname record'],
            explain: 'A CNAME maps one name to another. A returns IPv4, AAAA returns IPv6 and MX names a mail server.'
        },
        'tcp-handshake': {
            q: 'The second step of the three-way handshake is ______.',
            answer: 'SYN/ACK',
            accept: ['synack', 'syn-ack', 'syn ack'],
            explain: 'The server replies to the client SYN with SYN/ACK, and the client finishes with an ACK.'
        },
        'tls-sni': {
            q: 'TLS carries the requested hostname in the ______ extension.',
            answer: 'SNI',
            accept: ['server name indication'],
            explain: 'SNI travels in the Client Hello before encryption starts, so the hostname stays readable.'
        },
        'cdn-side': {
            q: 'The logo is downloaded from cdn.example.net on port ______.',
            answer: '80',
            explain: 'The second conversation is plain HTTP on port 80, not the HTTPS port 443.'
        },
        'record-types': {
            q: 'The AAAA record type returns an ______ address.',
            answer: 'IPv6',
            accept: ['ipv6 address'],
            explain: 'A returns IPv4 and AAAA returns IPv6. Both can exist for the same hostname.'
        },
        'follow-stream': {
            q: 'Right-click → Follow → ______ Stream reassembles a TCP conversation.',
            answer: 'TCP',
            explain: 'Follow TCP Stream joins the application payload in both directions so you can read the exchange once.'
        },

        'hierarchy': {
            q: 'Protocol Hierarchy lives under the ______ menu.',
            answer: 'Statistics',
            explain: 'Statistics → Protocol Hierarchy summarises the share of packets and bytes for each protocol.'
        },
        'conversations': {
            q: 'The Conversations column that identifies the busiest host is ______.',
            answer: 'Bytes',
            explain: 'Sorting by Bytes shows which address/port pair moved the most data, which is often more useful than packet count.'
        },
        'io-graph': {
            q: 'A flat line in an IO Graph means ______ traffic in that interval.',
            answer: 'no',
            accept: ['none', 'zero'],
            explain: 'The line stays at zero because no packets were captured during that interval.'
        },
        'endpoint-counts': {
            q: 'This capture contains ______ DNS packets.',
            answer: '6',
            explain: 'Three queries and three responses make six DNS packets in total.'
        },
        'http-objects': {
            q: 'The only exportable object in this conversation is ______.',
            answer: 'logo.png',
            accept: ['logo'],
            explain: 'The single successful HTTP response carries the PNG logo, so it is the only body HTTP Objects can export.'
        },
        'make-it-yours': {
            q: 'Mark a packet with the ______ shortcut.',
            answer: 'Ctrl+M',
            accept: ['ctrl m', 'ctrl+m'],
            explain: 'Ctrl+M marks the selected frame so it stays highlighted when filters change.'
        },

        'nxdomain': {
            q: 'DNS RCODE ______ means the name does not exist.',
            answer: '3',
            explain: 'RCODE 3 is NXDOMAIN. RCODE 0 means success and RCODE 5 means the query was refused.'
        },
        'connection-refused': {
            q: 'A closed TCP port answers a SYN with ______.',
            answer: 'RST/ACK',
            accept: ['rst', 'rst ack', 'rst-ack'],
            explain: 'The endpoint resets the attempt instead of completing the handshake when nothing is listening.'
        },
        'zero-window': {
            q: 'A zero receive window is shown by tcp.window == ______.',
            answer: '0',
            explain: 'A window value of 0 tells the sender to stop until the receiver advertises free buffer space again.'
        },
        'port-unreachable': {
            q: 'ICMP type ______ carries destination unreachable.',
            answer: '3',
            explain: 'Type 3 is destination unreachable. Code 3 within that type means the port is unreachable.'
        },
        'tls-alert': {
            q: 'TLS content type ______ carries an alert.',
            answer: '21',
            explain: 'Content type 21 is Alert, 22 is Handshake and 23 is Application Data.'
        },
        'stall': {
            q: 'The transfer stalls because the server advertises a ______ receive window.',
            answer: 'zero',
            explain: 'The server buffer is full, so its ACK advertises a zero window and the client stops sending.'
        },
        'reset-vs-unreachable': {
            q: 'No listener on a UDP port produces ICMP port ______.',
            answer: 'unreachable',
            explain: 'ICMP type 3 code 3 reports an unreachable UDP port. A TCP refusal would be a RST instead.'
        },
        'case-file': {
            q: 'Warnings and errors are aggregated by ______ Information.',
            answer: 'Expert',
            explain: 'Statistics → Expert Information groups checksum problems, retransmissions, resets and other warnings.'
        },

        'retransmission': {
            q: 'A retransmission repeats a sequence number and its ______.',
            answer: 'payload',
            accept: ['data'],
            explain: 'TCP resends the same sequence number and bytes when it believes the original was not acknowledged.'
        },
        'dup-acks': {
            q: '______ duplicate ACKs usually trigger fast retransmit.',
            answer: '3',
            accept: ['three'],
            explain: 'Three duplicate ACKs suggest one segment is missing, so the sender retransmits without waiting for the RTO.'
        },
        'fragments': {
            q: 'The last fragment clears the More ______ flag.',
            answer: 'Fragments',
            accept: ['fragment', 'mf'],
            explain: 'More Fragments stays set on every piece except the last one, which marks the end of the datagram.'
        },
        'fragment-set': {
            q: 'Fragments of one datagram share the IP ______ field.',
            answer: 'Identification',
            accept: ['id'],
            explain: 'The IP Identification value is copied into every fragment so the receiver can group and reassemble them.'
        },
        'payload-or-ack': {
            q: 'A pure ACK has tcp.len == ______.',
            answer: '0',
            explain: 'Pure ACKs carry no application bytes, so their TCP payload length is zero.'
        },
        'slow-transfer': {
            q: 'Repeated ACKs for the same number point to a missing ______.',
            answer: 'segment',
            accept: ['packet'],
            explain: 'The receiver keeps acknowledging the last contiguous byte because the next segment never arrived.'
        },

        'arp-spoof': {
            q: 'ARP maps an IP address to a ______ address.',
            answer: 'MAC',
            accept: ['mac address', 'hardware'],
            explain: 'ARP resolves an IPv4 address to the hardware address used on the local link.'
        },
        'port-scan': {
            q: 'An open port answers a scan SYN with ______.',
            answer: 'SYN/ACK',
            accept: ['synack', 'syn-ack', 'syn ack'],
            explain: 'An open TCP port completes the first half of the handshake, while a closed port returns RST/ACK.'
        },
        'dns-tunnel': {
            q: 'DNS record type ______ can carry arbitrary text.',
            answer: 'TXT',
            explain: 'TXT records hold free-form strings, which makes them a convenient carrier for encoded tunnel data.'
        },
        'malicious-upload': {
            q: 'A generic binary upload uses Content-Type application/______.',
            answer: 'octet-stream',
            accept: ['octet stream', 'octetstream'],
            explain: 'application/octet-stream means the server is being handed an opaque binary rather than a known document type.'
        },
        'c2-sni': {
            q: 'The requested TLS hostname is stored in the ______ extension.',
            answer: 'SNI',
            accept: ['server name indication'],
            explain: 'The SNI extension in the Client Hello names the server the client wants, even before encryption begins.'
        },
        'scan-result': {
            q: 'The scanner probed ______ destination ports.',
            answer: '9',
            accept: ['nine'],
            explain: 'Nine SYN attempts appear in the burst, which is a compact but obvious port scan.'
        },
        'decode-tunnel': {
            q: 'The base64 label aGVsbG8 decodes to ______.',
            answer: 'hello',
            explain: 'aGVsbG8 is the base64 encoding of hello, showing that readable data is moving inside the DNS labels.'
        },
        'threat-case': {
            q: 'The spoofed ______ reply redirected the gateway traffic.',
            answer: 'ARP',
            explain: 'The attacker announced the gateway IP from a different MAC, which sent local traffic through the attacker.'
        },

        'v6-neighbours': {
            q: 'IPv6 Neighbor Discovery uses solicited-node ______ instead of broadcast.',
            answer: 'multicast',
            explain: 'The solicitation goes to a derived multicast group so only the relevant neighbours process it.'
        },
        'v6-router': {
            q: 'ICMPv6 type ______ is Router Advertisement.',
            answer: '134',
            explain: 'Type 134 is Router Advertisement. Type 133 is Router Solicitation and 135 is Neighbor Solicitation.'
        },
        'v6-aaaa': {
            q: 'DNS type ______ returns an IPv6 address.',
            answer: '28',
            accept: ['aaaa'],
            explain: 'Type 28 is AAAA. Type 1 is A for IPv4 and type 16 is TXT.'
        },
        'v6-tls': {
            q: 'The IPv6 ______ Limit field caps how many routers a packet crosses.',
            answer: 'Hop',
            explain: 'Hop Limit replaces the IPv4 TTL. Each router decrements it and drops the packet at zero.'
        },
        'v6-echo': {
            q: 'ICMPv6 type ______ is an echo request.',
            answer: '128',
            explain: 'Type 128 is echo request and type 129 is echo reply, the IPv6 equivalents of ICMP types 8 and 0.'
        },
        'neighbour-types': {
            q: 'ICMPv6 type ______ is a Neighbor Solicitation.',
            answer: '135',
            explain: 'Type 135 asks for a neighbour address. Type 136 answers it with a Neighbor Advertisement.'
        },
        'v6-hop-limit': {
            q: 'A packet that arrives at a router with Hop Limit ______ is dropped.',
            answer: '1',
            accept: ['one'],
            explain: 'The router decrements the limit to zero, discards the packet and returns ICMPv6 Time Exceeded.'
        },

        'web-login': {
            q: 'A login form is normally submitted with the ______ method.',
            answer: 'POST',
            explain: 'POST carries form data in the request body, which is why a cleartext login is so sensitive.'
        },
        'web-redirect': {
            q: 'HTTP status ______ means Found, a temporary redirect.',
            answer: '302',
            explain: 'A 302 response points the browser at another URL, usually listed in the Location header.'
        },
        'web-cookies': {
            q: 'The ______ response header asks the browser to store a cookie.',
            answer: 'Set-Cookie',
            accept: ['set cookie', 'setcookie'],
            explain: 'Set-Cookie creates the cookie. The browser later returns it in the Cookie request header.'
        },
        'web-tracking': {
            q: 'The ______ header tells a tracker which page the user came from.',
            answer: 'Referer',
            accept: ['referrer'],
            explain: 'Referer carries the source page URL, which lets a third-party pixel tie the request to the visited site.'
        },
        'web-download': {
            q: 'The ______ header suggests the filename for a download.',
            answer: 'Content-Disposition',
            accept: ['content disposition', 'contentdisposition'],
            explain: 'Content-Disposition can include a filename that the browser suggests when saving the response body.'
        },
        'web-status': {
            q: 'HTTP ______ means the cached copy is still valid.',
            answer: '304',
            explain: '304 Not Modified tells the browser to reuse its cached copy instead of downloading the body again.'
        },
        'request-paths': {
            q: 'GET /______ returned the 404 response.',
            answer: 'missing',
            explain: 'The GET /missing request at #34 is answered with 404 Not Found, unlike /download which succeeds.'
        },
        'web-case': {
            q: 'This capture contains ______ HTTP requests.',
            answer: '6',
            explain: 'Six request packets appear, including the login POST, redirects, object fetches and the binary download.'
        },

        'tls-hellos': {
            q: 'This capture contains ______ TLS Client Hellos.',
            answer: '3',
            accept: ['three'],
            explain: 'Three sessions start with a Client Hello, each naming the host the client wants to reach.'
        },
        'tls-server-flight': {
            q: 'TLS handshake type ______ is Certificate.',
            answer: '11',
            explain: 'Type 11 carries the certificate chain. Type 1 is Client Hello and type 2 is Server Hello.'
        },
        'tls-sni-audit': {
            q: 'The suspicious update-like SNI is updates.bad-cdn.______.',
            answer: 'example',
            accept: ['updates.bad-cdn.example'],
            explain: 'updates.bad-cdn.example imitates an update service on a domain that does not match the organisation.'
        },
        'tls-alert-case': {
            q: 'TLS alert description ______ means handshake_failure.',
            answer: '40',
            explain: 'Description 40 is handshake_failure. Description 42 is bad_certificate and 70 is protocol_version.'
        },
        'tls-legacy': {
            q: 'TLS 1.0 is encoded as record version 0x______.',
            answer: '0301',
            accept: ['0x0301', '301'],
            explain: '0x0301 is TLS 1.0, 0x0303 is TLS 1.2 and 0x0304 is TLS 1.3.'
        },
        'tls-sessions': {
            q: 'The rejected session uses destination port ______.',
            answer: '8443',
            explain: 'The failed handshake targets 8443, while the other sessions use the usual HTTPS port 443.'
        },
        'certificates': {
            q: 'The Certificate handshake message is type ______.',
            answer: '11',
            explain: 'Type 11 is Certificate. Counting those messages shows how many servers actually sent a chain.'
        },
        'tls-case': {
            q: 'This capture contains ______ TLS records.',
            answer: '12',
            accept: ['twelve'],
            explain: 'Twelve records cover the three sessions, including hellos, certificates, alerts and application data.'
        },

        'mal-dga': {
            q: 'DNS RCODE ______ means NXDOMAIN.',
            answer: '3',
            explain: 'RCODE 3 is NXDOMAIN. Random generated domains usually fail with this code until one resolves.'
        },
        'mal-payload': {
            q: 'The MZ prefix shows the download is a Windows ______.',
            answer: 'executable',
            accept: ['exe', 'pe'],
            explain: 'MZ is the DOS header magic at the start of a Windows PE executable.'
        },
        'mal-user-agent': {
            q: 'The scripted Windows client uses the ______ User-Agent.',
            answer: 'WinHttp.WinHttpRequest',
            accept: ['winhttp', 'winhttp.winhttprequest.5.1'],
            explain: 'WinHttp is an HTTP library, not a browser, so its User-Agent exposes scripted traffic.'
        },
        'mal-beacon': {
            q: 'The beacon SNI is api.______.xyz.',
            answer: 'sync-telemetry',
            accept: ['api.sync-telemetry.xyz'],
            explain: 'The Client Hello requests api.sync-telemetry.xyz, which names the controller the implant is contacting.'
        },
        'mal-exfil': {
            q: 'The exfiltration chunks go to exfil.evil-cdn.______.',
            answer: 'top',
            accept: ['exfil.evil-cdn.top'],
            explain: 'Every TXT chunk sits under exfil.evil-cdn.top, the parent domain collecting the stolen data.'
        },
        'mal-gate': {
            q: 'The gate POST is sent with the ______ method.',
            answer: 'POST',
            explain: 'POST carries the encoded victim data in the request body to gate.php over port 80.'
        },
        'infra': {
            q: 'The executable is delivered by 203.0.113.______.',
            answer: '120',
            explain: '203.0.113.120 serves the stage2.exe download, while the C2 address is 198.51.100.77.'
        },
        'ports-chain': {
            q: 'The TLS beacon uses port ______.',
            answer: '443',
            explain: 'The beacon to api.sync-telemetry.xyz uses TLS on 443. Delivery and the gate use port 80.'
        },
        'mal-case': {
            q: 'The C2 host is 198.51.100.______.',
            answer: '77',
            explain: '198.51.100.77 receives the HTTPS beacon, the HTTP gate and the ICMP keepalive.'
        },

        'c2-heartbeat': {
            q: 'This capture contains ______ separate beacon sessions.',
            answer: '2',
            accept: ['two'],
            explain: 'Two Client Hellos to the beacon SNI show two separate check-in sessions.'
        },
        'c2-dns': {
            q: 'TXT lookups use DNS query type ______.',
            answer: '16',
            accept: ['txt'],
            explain: 'Type 16 is TXT. The numbered chunk labels under one parent domain carry the tunnelled data.'
        },
        'c2-http': {
            q: 'The fallback check-in uses the ______ User-Agent.',
            answer: 'curl/8.0',
            accept: ['curl', 'curl 8.0'],
            explain: 'curl/8.0 is a command-line client, which fits a scripted fallback rather than a user browsing.'
        },
        'c2-icmp': {
            q: 'ICMP type ______ is an echo request.',
            answer: '8',
            explain: 'Type 8 is echo request and type 0 is echo reply. Regular identifiers and sequence numbers suggest automation.'
        },
        'c2-jitter': {
            q: 'Beacons with small timing variation suggest a ______ interval.',
            answer: 'jittered',
            accept: ['jitter'],
            explain: 'A jittered interval adds small random delays so check-ins do not land on an exact fixed schedule.'
        },
        'channels': {
            q: '______ uses no TCP or UDP port.',
            answer: 'ICMP',
            explain: 'ICMP is carried directly in IP and has no ports, so port-based blocking cannot stop it.'
        },
        'fallback-survives': {
            q: 'The HTTP fallback uses port ______.',
            answer: '80',
            explain: 'The /api/v1/checkin request runs over plain HTTP on port 80, separate from the HTTPS beacon.'
        },
        'c2-case': {
            q: 'Every channel reaches 198.51.100.______.',
            answer: '77',
            explain: 'HTTPS, HTTP, DNS and ICMP all target the same controller address, 198.51.100.77.'
        }
    };

    CHAPTERS.forEach(function (chapter) {
        chapter.missions.forEach(function (mission) {
            var blank = FILL_BLANKS[mission.id];
            if (!blank) return;
            mission.tasks.push({
                text: 'Fill in the blank',
                blank: blank
            });
        });
    });

    window.ACADEMY_CHAPTERS = CHAPTERS;
})();

#include "types.hpp"

#include <array>
#include <cassert>
#include <chrono>
#include <cstring>
#include <deque>
#include <format>
#include <iostream>
#include <map>
#include <ostream>
#include <string.h>
#include <thread>
#include <vector>

using namespace std::chrono_literals;

// something to listen to while cracking the binary :D
// should be visible in 'strings' output or something
static volatile char mood[] = "https://www.youtube.com/watch?v=_W1P7AvV17w";

typedef u16 mac_addr;
typedef u32 ip_addr;

struct net_switch;
struct net_router;
struct net_pc;

constexpr u16 broadcast_mac = 0xFFFF;
constexpr u32 subnetmask = 0xFFFFFF00;

#define CONNECT(INT_A, INT_B) { \
	INT_A.connection = &INT_B; \
	INT_B.connection = &INT_A; \
}

consteval int ip_to_int(int octet_1, int octet_2, int octet_3, int octet_4)
{
	return (octet_1 << 24) | (octet_2 << 16) | (octet_3 << 8) | octet_4;
}

std::string ip_to_str(ip_addr ip)
{
	return std::format("{}.{}.{}.{}",
			(ip >> 24) & 0xFF,
			(ip >> 16) & 0xFF,
			(ip >> 8) & 0xFF,
			ip & 0xFF);
}

// internally the addresses are thought of as x.x.x.x
ip_addr str_to_ip(const std::string& str)
{
	std::array<i32, 4> nums;
	std::sscanf(str.c_str(), "%d.%d.%d.%d", &nums[3], &nums[2], &nums[1], &nums[0]);

	return  ((nums[3] & 0xFF) << 24) |
			((nums[2] & 0xFF) << 16) |
			((nums[1] & 0xFF) << 8) |
			(nums[0] & 0xFF);
}

u32 adler_32(const u8* const data, const u64 size)
{
	u16 a{1}, b{0};

	for (u64 i = 0; i < size; ++i)
	{
		a = (a + data[i]) % 65521;
		b = (a + b) % 65521;
	}

	u32 checksum = b;
	checksum <<= 16;
	checksum += a;

	return checksum;
}

u16 fletcher_16(const u8* const data, const u64 size)
{
	uint16_t a{0}, b{0};

	for (u64 i = 0; i < size; ++i)
	{
		a = (a + data[i]) % 255;
		b = (a + b) % 255;
	}

	return (b << 8) | a;
}

struct port_table_entry
{
	mac_addr mac;
	u8 port;
};

struct port_table
{
	std::vector<port_table_entry> entries;
};

struct frame
{
	mac_addr src;
	mac_addr dst;
	u16 payload_length;
	u8 payload[1200];
};

struct network_device;

struct net_interface
{
	mac_addr mac = rand();
	std::optional<ip_addr> ip;
	std::deque<frame> frames;

	net_interface* connection = nullptr;
	network_device* parent = nullptr;
};

enum class payload_type : u8
{
	ipv4 = 0, arp_request = 1, arp_reply = 2
};

struct __attribute__((packed)) arp_request
{
	const payload_type signature = payload_type::arp_request;
	ip_addr ip;
};

struct __attribute__((packed)) arp_reply
{
	const payload_type signature = payload_type::arp_reply;
	ip_addr ip;
	mac_addr mac;
};

struct packet
{
	const payload_type signature = payload_type::ipv4;
	ip_addr src;
	ip_addr dst;
	u8 time_to_live = 32;

	std::string payload;
};


bool is_same_subnet(ip_addr a, ip_addr b)
{
	return (a & 0xFFFFFF00) == (b & 0xFFFFFF00);
}

struct network_device
{
	network_device()
	{
		for (net_interface& net_int : interfaces)
			net_int.parent = this;
	}

	virtual bool run() = 0;
	std::array<net_interface, 5> interfaces;

	void send_arp_request(const ip_addr dest_ip, const u16 interface)
	{
#ifndef NDEBUG
		std::cout << "sending out an ARP request\n";
#endif
		frame f;
		f.src = interfaces[interface].mac;
		f.dst = broadcast_mac;

		arp_request arp;
		arp.ip = dest_ip;
		f.payload_length = sizeof(arp);
		memcpy(f.payload, &arp, sizeof(arp));

		interfaces.at(interface).connection->frames.push_back(f);
		interfaces.at(interface).connection->parent->run();
	};

	void send_frame_to_interface(frame f, u8 interface)
	{
		assert(interface < interfaces.size());
		assert(interfaces[interface].connection != nullptr);
		interfaces[interface].connection->frames.push_back(f);
	}

	// reply to ARP request that was received in
	// a specific interface
	void reply_to_arp(const u16 receiving_interface, const frame f)
	{
		assert(interfaces[receiving_interface].ip.has_value());

		arp_request* arp = (arp_request*)&f.payload;

		// check if we are the recipient
		if (arp->ip != interfaces[receiving_interface].ip.value())
		{
#ifndef NDEBUG
			std::cout << "dropping frame\n";
#endif
			return;
		}

#ifndef NDEBUG
		std::cout << "hey, that's us!\n";
#endif

		// reply
		arp_reply arp_rep;
		arp_rep.ip = interfaces[receiving_interface].ip.value();
		arp_rep.mac = interfaces[receiving_interface].mac;

		frame reply_frame;
		reply_frame.src = interfaces[receiving_interface].mac;
		assert(f.src != broadcast_mac);
		reply_frame.dst = f.src;
		reply_frame.payload_length = sizeof(arp_reply);
		memcpy(reply_frame.payload, &arp_rep, sizeof(arp_reply));

		interfaces[receiving_interface].connection->frames.push_back(reply_frame);
		interfaces[receiving_interface].connection->parent->run();
	}
};

struct net_pc : public network_device
{
	net_pc(ip_addr ip)
	{
		interfaces.at(0).ip = ip;

		// pre-populate the mac table with our own MAC just
		// in case someone has the good idea of sending traffic
		// to themselves
		mac_table[ip] = interfaces.at(0).mac;

		// initialize ram with all zeroes
		memset(ram, 0, sizeof(u8) * ram_size);
	}

	bool run() override
	{
		if (interfaces[0].frames.empty())
			return false;

		if (interfaces[0].connection == nullptr)
			return false;

		frame f = interfaces[0].frames[0];
		interfaces[0].frames.pop_front();

#ifndef NDEBUG
		std::cout << std::format("> pc {} received a frame from {}\n", ip_to_str(interfaces[0].ip.value()), f.src);
#endif

		payload_type type = (payload_type)f.payload[0];
		switch (type)
		{
			case payload_type::ipv4:
			{
#ifndef NDEBUG
				std::cout << "type: ipv4\n";
#endif
				packet* p = (packet*)&f.payload;

				// check if we are the correct recipient
				if (p->dst != interfaces[0].ip.value())
				{
#ifndef NDEBUG
					std::cout << "dropping packet, we are not the recipient\n";
#endif
					break;
				}

				// handlers for generic messages
				if (p->payload == "ping")
				{
#ifndef NDEBUG
					std::cout << "got a ping, responding with 'pong'\n";
#endif

					// send a "pong" in response
					packet pong;
					pong.src = interfaces[0].ip.value();
					pong.dst = p->src;
					pong.payload = "pong";
					send_packet(pong);
					break;
				}

#ifndef NDEBUG
				if (p->payload == "pong")
				{
					std::cout << "got a 'pong'\n";
					break;
				}
#endif

				if (ipv4_handler == nullptr)
				{
#ifndef NDEBUG
					std::cout << "no ipv4 handler, dropping packet\n";
#endif
					break;
				}

				ipv4_handler(this, p);
				break;
			}

			case payload_type::arp_request:
			{
#ifndef NDEBUG
				std::cout << "type: arp\n";
#endif
				reply_to_arp(0, f);
				break;
			}

			case payload_type::arp_reply:
			{
#ifndef NDEBUG
				std::cout << "type: arp reply\n";
#endif

				arp_reply* arp = (arp_reply*)&f.payload;
#ifndef NDEBUG
				std::cout << arp->mac << " -> " << ip_to_str(arp->ip) << '\n';
#endif

				// store the result
				mac_table[arp->ip] = arp->mac;

				break;
			}
		}

		return true;
	}

	void send_packet(packet p)
	{
#ifndef NDEBUG
		std::cout << std::format("{} ({}) -> {}\n", ip_to_str(p.src), interfaces[0].mac, ip_to_str(p.dst));
#endif

		// check if the IP is within the same network
		if (!is_same_subnet(p.src, p.dst))
		{
			// send the packet to the gateway (always .1)
			// if we don't yet know its mac address, figure it out
			// with ARP
			const ip_addr gateway_ip = (interfaces[0].ip.value() & 0xFFFFFF00) | 0x1;

			if (!mac_table.contains(gateway_ip))
				send_arp_request(gateway_ip, 0);

			assert(mac_table.contains(gateway_ip));

			// encapsulate the packet and send it to the gateway
			frame f;
			f.src = interfaces[0].mac;
			f.dst = mac_table.at(gateway_ip);
			f.payload_length = sizeof(packet);
			memcpy(f.payload, &p, sizeof(packet));

			interfaces[0].connection->frames.push_back(f);
			interfaces[0].connection->parent->run();

			return;
		}

		// check if we are sending traffic to ourselves
		// as in those cases we can just throw the frame into
		// our own interface instead of sending it to a switch
		if (p.dst == interfaces[0].ip.value())
		{
			frame f;
			f.src = interfaces[0].mac;
			f.dst = interfaces[0].mac;
			f.payload_length = sizeof(packet);
			memcpy(f.payload, &p, sizeof(packet));
			interfaces[0].frames.push_back(f);
			interfaces[0].parent->run();
			return;
		}

		// check if we have the mac address of the receiver
		if (!mac_table.contains(p.dst))
			send_arp_request(p.dst, 0);

		// if there is no such receiver, don't send anything
		if (!mac_table.contains(p.dst))
			return;

		// encapsulate the frame into a packet and send it out
		frame f;
		f.src = interfaces[0].mac;
		f.dst = mac_table.at(p.dst);
		f.payload_length = sizeof(packet);
		memcpy(f.payload, &p, sizeof(packet));

		interfaces[0].connection->frames.push_back(f);
		interfaces[0].connection->parent->run();
	}

	void respond_to_packet(const packet* const p, const std::string& payload)
	{
		packet response;
		response.src = interfaces[0].ip.value();
		response.dst = p->src;
		response.payload = payload;
		send_packet(response);
	}

	std::map<ip_addr, mac_addr> mac_table;
	void (*ipv4_handler)(net_pc* pc, packet* p) = nullptr;

	// some random access memory so that the computer
	// can keep state between sending and receiving stuff
	static constexpr u32 ram_size = 256;
	u8 ram[ram_size];
};

struct net_switch : public network_device
{
	std::map<mac_addr, u8> switching_table;

	bool run() override
	{
		// check if any of the interfaces have received frames
		for (u16 i = 0; i < interfaces.size(); ++i)
		{
			if (interfaces[i].frames.empty())
				continue;

			if (interfaces[i].connection == nullptr)
				continue;

#ifndef NDEBUG
			std::cout << std::format("> switch has received a frame on int[{}]\n", i);
#endif

			// get the frame
			frame f = interfaces[i].frames[0];
			interfaces[i].frames.pop_front();
			assert(f.dst != f.src);

			// learn the mac address
#ifndef NDEBUG
			if (switching_table.contains(f.src))
				assert(switching_table.at(f.src) == i);
#endif

			switching_table[f.src] = i;

			// if the destination MAC is equal to the broadcast one, send the frame
			// out from all interfaces except the one it was received
			// from
			//
			// also broadcast if the destination is unknown
			if (f.dst == broadcast_mac || !switching_table.contains(f.dst))
			{
#ifndef NDEBUG
				std::cout << "#broadcasting\n";
#endif

				for (u16 j = 0; j < interfaces.size(); ++j)
				{
					if (interfaces[j].connection == nullptr)
						continue;

					if (j == i)
						continue;

					interfaces[j].connection->frames.push_back(f);
					interfaces[j].connection->parent->run();
				}

				return true;
			}

			// send the frame out of the correct port
#ifndef NDEBUG
			std::cout << "sending frame out from port " << (u16)switching_table.at(f.dst) << '\n';
#endif
			interfaces[switching_table.at(f.dst)].connection->frames.push_back(f);
			interfaces[switching_table.at(f.dst)].connection->parent->run();

			return true;
		}

		return false;
	}
};

struct net_router : public network_device
{
	bool run() override
	{
		// check if any of the interfaces have received frames
		for (u16 i = 0; i < interfaces.size(); ++i)
		{
			if (interfaces[i].frames.empty())
				continue;

			if (interfaces[i].connection == nullptr)
				continue;

			frame f = interfaces[i].frames[0];
			interfaces[i].frames.pop_front();
			assert(f.dst != f.src);

#ifndef NDEBUG
			std::cout << std::format("> router {} received a frame from {}\n", ip_to_str(interfaces[i].ip.value()), f.src);
			std::cout << "port mac: " << interfaces[i].mac << '\n';
#endif

			payload_type type = (payload_type)f.payload[0];
			switch(type)
			{
				case payload_type::ipv4:
				{
#ifndef NDEBUG
					std::cout << "type: ipv4\n";
#endif

					packet* p = (packet*)&f.payload;
					const ip_addr target_net = p->dst & subnetmask;

					if (!routing_table.contains(target_net))
					{
						if (!default_route.has_value())
						{
#ifndef NDEBUG
							std::cout << "no route for network " << ip_to_str(target_net) << "/24, dropping packet\n";
#endif
							break;
						}

#ifndef NDEBUG
						std::cout << "using default route\n";
#endif
						f.src = interfaces[default_route.value()].mac;
						f.dst = interfaces[default_route.value()].connection->mac;
						interfaces[default_route.value()].connection->frames.push_back(f);
						interfaces[default_route.value()].connection->parent->run();
						break;
					}

					const u16 forward_interface = routing_table.at(target_net);
#ifndef NDEBUG
					std::cout << "forwarding packet to interface " << forward_interface << '\n';
#endif

					f.src = interfaces[forward_interface].mac;
					f.dst = interfaces[forward_interface].connection->mac;
					interfaces[forward_interface].connection->frames.push_back(f);
					interfaces[forward_interface].connection->parent->run();

					break;
				}

				case payload_type::arp_request:
				{
#ifndef NDEBUG
					std::cout << "type: arp\n";
#endif
					reply_to_arp(i, f);
					break;
				}

				case payload_type::arp_reply:
				{

					arp_reply* arp = (arp_reply*)&f.payload;

#ifndef NDEBUG
					std::cout << "type: arp reply\n";
					std::cout << arp->mac << " -> " << ip_to_str(arp->ip) << '\n';
#endif

					// store the result
					mac_table[arp->ip] = arp->mac;

					break;
				}

				default:
				{
#ifndef NDEBUG
					std::cout << "dropping frame of type " << (u16)type << '\n';
#endif
					break;
				}
			}
		}

		return false;
	}

	// the ip addr should be the /24 prefix of the target network
	// the other value is the next-hop interface
	std::map<ip_addr, u16> routing_table;

	// if set, send all unknown target traffic to this interface
	std::optional<u16> default_route;

	std::map<ip_addr, mac_addr> mac_table;
};

static constexpr ip_addr user_ip = ip_to_int(38, 15, 199, 42);
static constexpr ip_addr xor_pc = ip_to_int(83, 48, 92, 8);
static constexpr ip_addr pc1_ip = ip_to_int(38, 15, 199, 41);
static constexpr ip_addr pc2_ip = ip_to_int(38, 15, 199, 40);
static constexpr ip_addr pc3_ip = ip_to_int(64, 14, 3, 25);
static constexpr ip_addr pc4_ip = ip_to_int(64, 14, 3, 29);
static constexpr ip_addr pc5_ip = ip_to_int(100, 25, 26, 11);
static constexpr ip_addr pc7_ip = ip_to_int(100, 25, 26, 15);
static constexpr ip_addr pc8_ip = ip_to_int(83, 48, 92, 5);

static constexpr u8 xor_key = 0x42;

int main()
{
#ifndef NDEBUG
	srand(123);
#else
	// fully randomize the MAC addresses in release builds
	// for some extra fun times
	srand(time(0));
#endif

	// user network 38.15.199.0/24

	net_switch Switch0;

	net_pc user_pc(user_ip);
	user_pc.interfaces[0].mac = 42;

	net_pc pc1(pc1_ip);
	net_pc pc2(pc2_ip);

	CONNECT(user_pc.interfaces[0], Switch0.interfaces[4]);
	CONNECT(pc1.interfaces[0], Switch0.interfaces[2]);
	CONNECT(pc2.interfaces[0], Switch0.interfaces[3]);

	user_pc.ipv4_handler = [](net_pc* pc, packet* p)
	{
		// just print out whatever getes sent our way
		std::cout << " \033[1;36mreceived:\033[0m " << p->payload << "\n";
	};

	pc1.ipv4_handler = [](net_pc* pc, packet* p)
	{
		if (p->src == user_ip)
		{
			pc->respond_to_packet(p, "My complicated firewall rules told me to not talk to you");
			return;
		}

		// in case anyone other than the user sent data,
		// format it as a flag and send it to the user

		const std::string characters = "abcdefghijklmnopqrstuvwxyz0123456789_";

		std::string flag = "CMO{secret_code_";
		for (size_t i = 0; i < p->payload.size(); ++i)
		{
			flag.push_back(characters.at((p->payload.at(i) + i) % characters.size()));
		}

		flag.push_back('}');

		packet user_packet;
		user_packet.src = pc->interfaces[0].ip.value();
		user_packet.dst = user_ip;
		user_packet.payload = flag;
		pc->send_packet(user_packet);
	};

	pc2.ipv4_handler = [](net_pc* pc, packet* p)
	{
		pc->respond_to_packet(p, "OK");
	};

	// transit core

	net_router Router3;
	Router3.interfaces[2].ip = ip_to_int(38, 15, 199, 1);
	Router3.interfaces[0].ip = ip_to_int(42, 20, 102, 1);
	Router3.default_route = 0;
	Router3.routing_table[ip_to_int(38, 15, 199, 0)] = 2;

	net_router Router4;
	Router4.interfaces[0].ip = ip_to_int(42, 20, 102, 2);
	Router4.interfaces[1].ip = ip_to_int(185, 23, 59, 2);
	Router4.interfaces[2].ip = ip_to_int(85, 34, 39, 1);
	Router4.routing_table[ip_to_int(38, 15, 199, 0)] = 0;
	Router4.routing_table[ip_to_int(83, 48, 92, 0)] = 1;
	Router4.routing_table[ip_to_int(100, 25, 26, 0)] = 2;
	Router4.routing_table[ip_to_int(64, 14, 3, 0)] = 2;

	CONNECT(Switch0.interfaces[1], Router3.interfaces[2]);
	CONNECT(Router3.interfaces[0], Router4.interfaces[0]);

	net_router Router6;
	Router6.interfaces[0].ip = ip_to_int(85, 34, 39, 2);
	Router6.interfaces[1].ip = ip_to_int(64, 14, 3, 1);
	Router6.interfaces[2].ip = ip_to_int(100, 25, 26, 1);
	Router6.routing_table[ip_to_int(38, 15, 199, 0)] = 0;
	Router6.routing_table[ip_to_int(83, 48, 92, 0)] = 0;
	Router6.routing_table[ip_to_int(100, 25, 26, 0)] = 2;
	Router6.routing_table[ip_to_int(64, 14, 3, 0)] = 1;

	CONNECT(Router6.interfaces[0], Router4.interfaces[2]);

	// target network 100.25.26.0/24

	net_switch Switch1;

	net_pc target_pc(ip_to_int(100, 25, 26, 10));
	target_pc.ipv4_handler = [](net_pc* pc, packet* p)
	{
		static constexpr u16 memory_magic = 0xCAFE;

		struct __attribute__((packed)) memory
		{
			const u16 magic = memory_magic;
			bool rec_user = false;
			char* orig_payload = nullptr; // payload without magic bytes
			char* pc3_response = nullptr;
			char* pc4_response = nullptr;
			char* pc7_response = nullptr;
			char* pc9_response = nullptr;
		};

		const auto is_ram_initialized = [pc]()
		{
			return reinterpret_cast<u16*>(pc->ram)[0] == memory_magic;
		};

		if (!is_ram_initialized())
		{
			memory m;
			memcpy(pc->ram, &m, sizeof(memory));
		}

		memory* mem = reinterpret_cast<memory*>(pc->ram);

		if (p->src == user_ip)
		{
			mem->rec_user = true;
			assert(mem->pc3_response == nullptr);
			assert(mem->pc4_response == nullptr);
			assert(mem->pc7_response == nullptr);

			// check if the message starts with the valid prefix
			if (!p->payload.starts_with("msg_"))
			{
				pc->respond_to_packet(p, "I don't want to talk to you");
				return;
			}

			// remove the prefix
			p->payload.erase(0, strlen("msg_"));

			// if there's nothing left after removing the prefix, send
			// a different response
			if (p->payload.empty())
			{
				pc->respond_to_packet(p, "So you had nothing to say?");
				return;
			}

			mem->orig_payload = (char*)malloc(sizeof(char) * p->payload.size() + 1);
			strncpy(mem->orig_payload, p->payload.data(), p->payload.size());
			mem->orig_payload[p->payload.size()] = 0;

			// XOR the payload with the help of pc9
			packet xor_packet;
			xor_packet.src = pc->interfaces[0].ip.value();
			xor_packet.dst = xor_pc;
			xor_packet.payload = p->payload;
			pc->send_packet(xor_packet);
		}

		// got the XORed string, start sending it out to the rest of the computers
		// the next one should be pc3
		if (p->src == xor_pc)
		{
			mem->pc9_response = (char*)malloc(sizeof(char) * p->payload.size() + 1);
			strncpy(mem->pc9_response, p->payload.data(), p->payload.size());
			mem->pc9_response[p->payload.size()] = 0;

			packet pc3_packet;
			pc3_packet.src = pc->interfaces[0].ip.value();
			pc3_packet.dst = pc3_ip;
			pc3_packet.payload = mem->pc9_response;
			pc->send_packet(pc3_packet);

			return;
		}

		// got the response from pc3
		// send the next packet to pc4
		if (p->src == pc3_ip)
		{
			mem->pc3_response = (char*)malloc(sizeof(char) * p->payload.size() + 1);
			strncpy(mem->pc3_response, p->payload.data(), p->payload.size());
			mem->pc3_response[p->payload.size()] = 0;

			packet pc4_packet;
			pc4_packet.src = pc->interfaces[0].ip.value();
			pc4_packet.dst = pc4_ip;
			pc4_packet.payload = mem->pc9_response;
			pc->send_packet(pc4_packet);

			return;
		}

		// got the response from pc4
		// send the next packet to pc7
		if (p->src == pc4_ip)
		{
			mem->pc4_response = (char*)malloc(sizeof(char) * p->payload.size() + 1);
			strncpy(mem->pc4_response, p->payload.data(), p->payload.size());
			mem->pc4_response[p->payload.size()] = 0;

			packet pc7_packet;
			pc7_packet.src = pc->interfaces[0].ip.value();
			pc7_packet.dst = pc7_ip;
			pc7_packet.payload = mem->pc9_response;
			pc->send_packet(pc7_packet);

			return;
		}

		// got the response from pc7
		// form the final opinion and send the result to the user pc
		if (p->src == pc7_ip)
		{
			mem->pc7_response = (char*)malloc(sizeof(char) * p->payload.size() + 1);
			strncpy(mem->pc7_response, p->payload.data(), p->payload.size());
			mem->pc7_response[p->payload.size()] = 0;

			assert(mem->pc3_response != nullptr);
			assert(mem->pc4_response != nullptr);
			assert(mem->pc7_response != nullptr);
			assert(mem->pc9_response != nullptr);

			u32 len{0}, hash{0};

			try
			{
				len = std::stoi(mem->pc3_response);
				hash = std::stoi(mem->pc4_response);
			}
			catch (const std::exception& e)
			{
				// tell the user that its rude to send crashing data
				packet response;
				response.src = pc->interfaces[0].ip.value();
				response.dst = user_ip;
				response.payload = "You ain't gonna crash my computer with that";
				pc->send_packet(response);
				return;
			};
			const bool is_even_printable = mem->pc7_response[0] == '1';

#ifndef NDEBUG
			std::cout << "len: " << len << '\n';
			std::cout << "hash: " << hash << '\n';
			std::cout << "is even and printable: " << is_even_printable << '\n';
#endif

			const std::string orig_payload = mem->orig_payload;

			free(mem->orig_payload);
			free(mem->pc3_response);
			free(mem->pc4_response);
			free(mem->pc7_response);
			free(mem->pc9_response);

			// if things match up, send the user message to the flag forwarder (pc1)
			if (len == 8 && hash == 100806214 && is_even_printable)
			{
				// make sure that the real strlen agrees with our fancy
				// strlen result
				assert(strlen(orig_payload.c_str()) == len);

				packet pc1_packet;
				pc1_packet.src = pc->interfaces[0].ip.value();
				pc1_packet.dst = pc1_ip;
				pc1_packet.payload = orig_payload;

				pc->send_packet(pc1_packet);
				return;
			}

			// if things did not match up, give a fitting response
			packet response;
			response.src = pc->interfaces[0].ip.value();
			response.dst = user_ip;
			response.payload = "I don't want to talk to you";
			pc->send_packet(response);

			return;
		}

#ifndef NDEBUG
		std::cout << "got the following message: " << p->payload << '\n';
#endif
	};

	net_pc pc5(pc5_ip);
	net_pc pc7(pc7_ip);

	CONNECT(Switch1.interfaces[1], Router6.interfaces[2]);
	CONNECT(Switch1.interfaces[3], target_pc.interfaces[0]);
	CONNECT(Switch1.interfaces[2], pc5.interfaces[0]);
	CONNECT(Switch1.interfaces[4], pc7.interfaces[0]);

	pc5.ipv4_handler = [](net_pc* pc, packet* p)
	{
		// don't allow an infinite loop to happen by accident
		if (p->src == pc->interfaces[0].ip.value())
			return;

		// start a small denial of service attack :D
		for (int i = 0; i < 4096; ++i)
		{
			ip_addr ip = rand();

			packet new_packet;
			new_packet.src = pc->interfaces[0].ip.value();
			new_packet.dst = ip;
			new_packet.payload = "HI THERE!!";

			std::this_thread::sleep_for(1ms);
			pc->send_packet(new_packet);
		}

		// tell the sender what we just did
		packet user_packet;
		user_packet.src = pc->interfaces[0].ip.value();
		user_packet.dst = p->src;
		user_packet.payload = "Okay, I did some spamming. You are welcome!";
		pc->send_packet(user_packet);
	};

	pc7.ipv4_handler = [](net_pc* pc, packet* p)
	{
		// un XOR the payload (see the comment in pc3 handler)
		if (p->src != xor_pc)
		{
			// store the sender address to RAM
			memcpy(pc->ram, &p->src, sizeof(ip_addr));

			packet undecipher;
			undecipher.src = pc->interfaces[0].ip.value();
			undecipher.dst = xor_pc;
			undecipher.payload = p->payload;
			pc->send_packet(undecipher);
			return;
		}

		// fetch the original sender address from RAM
		ip_addr orig_sender;
		memcpy(&orig_sender, pc->ram, sizeof(ip_addr));

		// check if all characters in the string have even
		// numeric values
		bool is_even = true;
		for (char c : p->payload)
			is_even &= !(c & 1);

		// check if the characters are printable
		bool is_printable = true;
		for (char c : p->payload)
			is_printable &= (c > 32) && (c < 127);

		packet response;
		response.src = pc->interfaces[0].ip.value();
		response.dst = orig_sender;
		response.payload = (is_even && is_printable) ? "1" : "0";
		pc->send_packet(response);
	};

	// 64.14.3.0/24

	net_switch Switch2;

	net_pc pc3(pc3_ip);
	net_pc pc4(pc4_ip);

	CONNECT(Switch2.interfaces[1], Router6.interfaces[1]);
	CONNECT(Switch2.interfaces[2], pc3.interfaces[0]);
	CONNECT(Switch2.interfaces[3], pc4.interfaces[0]);

	pc3.ipv4_handler = [](net_pc* pc, packet* p)
	{
		// if the packet was not received from PC9, send it to that
		// PC9 will respond and thus the other branch should also get executed
		// which gives us the opportunity to respond to the original sender
		if (p->src != xor_pc)
		{
			// store the sender address to RAM
			memcpy(pc->ram, &p->src, sizeof(ip_addr));

			packet undecipher;
			undecipher.src = pc->interfaces[0].ip.value();
			undecipher.dst = xor_pc;
			undecipher.payload = p->payload;
			pc->send_packet(undecipher);
			return;
		}

		// and yes, I know that XOR won't change the result at all :D
		// the detour to PC9 in this case is just extra noise and it
		// hopefully makes debugging slightly more annoying

		// fetch the original sender address from RAM
		ip_addr orig_sender;
		memcpy(&orig_sender, pc->ram, sizeof(ip_addr));

		const size_t len = p->payload.size();
		const std::string string_length_str = std::to_string(len);

		packet response;
		response.src = pc->interfaces[0].ip.value();
		response.dst = orig_sender;
		response.payload = string_length_str;
		pc->send_packet(response);
	};

	pc4.ipv4_handler = [](net_pc* pc, packet* p)
	{
		// un XOR the payload (see the comment in pc3 handler)
		if (p->src != xor_pc)
		{
			// store the sender address to RAM
			memcpy(pc->ram, &p->src, sizeof(ip_addr));

			packet undecipher;
			undecipher.src = pc->interfaces[0].ip.value();
			undecipher.dst = xor_pc;
			undecipher.payload = p->payload;
			pc->send_packet(undecipher);
			return;
		}

		// fetch the original sender address from RAM
		ip_addr orig_sender;
		memcpy(&orig_sender, pc->ram, sizeof(ip_addr));

		const u32 adler_hash = adler_32((u8*)p->payload.c_str(), p->payload.size() * sizeof(char));
		const u32 fletcher_hash = fletcher_16((u8*)p->payload.c_str(), p->payload.size() * sizeof(char));

		// a small position dependent check to prevent
		// hash collisions
		u32 shift_checksum = 0;
		for (size_t i = 0; i < p->payload.size(); ++i)
			shift_checksum += (p->payload[i]) << i;

		// check if the string is a palindrome
		// and multiple the hash with the boolean result
		bool is_palindrome = true;
		for (size_t i = 0; i < p->payload.size() / 2; ++i)
			is_palindrome &= p->payload[i] == p->payload[p->payload.size() - i - 1];

		const u32 combined_hash = ((adler_hash ^ fletcher_hash) * is_palindrome) ^ shift_checksum;

		packet response;
		response.src = pc->interfaces[0].ip.value();
		response.dst = orig_sender;
		response.payload = std::to_string(combined_hash);
		pc->send_packet(response);
	};

	// 185.23.59.0/24

	net_router Router5;
	Router5.interfaces[0].ip = ip_to_int(185, 23, 59, 1);
	Router5.interfaces[1].ip = ip_to_int(83, 48, 92, 1);
	Router5.default_route = 0;
	Router5.routing_table[ip_to_int(83, 48, 92, 0)] = 1;

	CONNECT(Router5.interfaces[0], Router4.interfaces[1]);

	// 83.48.92.0/24

	net_switch Switch3;

	net_pc pc8(pc8_ip);
	net_pc pc9(xor_pc);

	CONNECT(Switch3.interfaces[0], Router5.interfaces[1]);
	CONNECT(Switch3.interfaces[2], pc8.interfaces[0]);
	CONNECT(Switch3.interfaces[3], pc9.interfaces[0]);

	// the "XOR" pc
	pc9.ipv4_handler = [](net_pc* pc, packet* p)
	{
#ifndef NDEBUG
		std::cout << "the XOR machine shall respond\n";
#endif

		std::string data = p->payload;
		for (char& c : data)
		{
			if (c == xor_key)
			{
				pc->respond_to_packet(p, "...");
				return;
			}

			c ^= xor_key;
		}

		assert(data.size() == p->payload.size());

		packet response;
		response.src = pc->interfaces[0].ip.value();
		response.dst = p->src;
		response.payload = data;
		pc->send_packet(response);
	};

	std::cout << "     \033[1;36mwhat:\033[0m " << std::flush;
	std::string msg;
	std::getline(std::cin, msg);

	std::cout << "    \033[1;36mwhere:\033[0m " << std::flush;
	std::string dest_ip_str;
	std::getline(std::cin, dest_ip_str);

	// send off the packet
	packet p;
	p.src = user_pc.interfaces[0].ip.value();
	p.dst = str_to_ip(dest_ip_str);
	p.payload = msg;
	user_pc.send_packet(p);
}

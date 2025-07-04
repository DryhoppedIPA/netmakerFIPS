package logic

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/goombaio/namegenerator"
	"github.com/gravitl/netmaker/database"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/logic/acls"
	"github.com/gravitl/netmaker/models"
	"github.com/gravitl/netmaker/servercfg"
	"golang.org/x/exp/slog"
)

var (
	extClientCacheMutex = &sync.RWMutex{}
	extClientCacheMap   = make(map[string]models.ExtClient)
)

func getAllExtClientsFromCache() (extClients []models.ExtClient) {
	extClientCacheMutex.RLock()
	for _, extclient := range extClientCacheMap {
		if extclient.Mutex == nil {
			extclient.Mutex = &sync.Mutex{}
		}
		extClients = append(extClients, extclient)
	}
	extClientCacheMutex.RUnlock()
	return
}

func deleteExtClientFromCache(key string) {
	extClientCacheMutex.Lock()
	delete(extClientCacheMap, key)
	extClientCacheMutex.Unlock()
}

func getExtClientFromCache(key string) (extclient models.ExtClient, ok bool) {
	extClientCacheMutex.RLock()
	extclient, ok = extClientCacheMap[key]
	if extclient.Mutex == nil {
		extclient.Mutex = &sync.Mutex{}
	}
	extClientCacheMutex.RUnlock()
	return
}

func storeExtClientInCache(key string, extclient models.ExtClient) {
	extClientCacheMutex.Lock()
	if extclient.Mutex == nil {
		extclient.Mutex = &sync.Mutex{}
	}
	extClientCacheMap[key] = extclient
	extClientCacheMutex.Unlock()
}

// ExtClient.GetEgressRangesOnNetwork - returns the egress ranges on network of ext client
func GetEgressRangesOnNetwork(client *models.ExtClient) ([]string, error) {

	var result []string
	networkNodes, err := GetNetworkNodes(client.Network)
	if err != nil {
		return []string{}, err
	}
	for _, currentNode := range networkNodes {
		if currentNode.Network != client.Network {
			continue
		}
		if currentNode.IsEgressGateway { // add the egress gateway range(s) to the result
			if len(currentNode.EgressGatewayRanges) > 0 {
				result = append(result, currentNode.EgressGatewayRanges...)
			}
		}
	}
	extclients, _ := GetNetworkExtClients(client.Network)
	for _, extclient := range extclients {
		if extclient.ClientID == client.ClientID {
			continue
		}
		result = append(result, extclient.ExtraAllowedIPs...)
	}

	return result, nil
}

// DeleteExtClient - deletes an existing ext client
func DeleteExtClient(network string, clientid string) error {
	key, err := GetRecordKey(clientid, network)
	if err != nil {
		return err
	}
	extClient, err := GetExtClient(clientid, network)
	if err != nil {
		return err
	}
	err = database.DeleteRecord(database.EXT_CLIENT_TABLE_NAME, key)
	if err != nil {
		return err
	}
	if servercfg.CacheEnabled() {
		// recycle ip address
		if extClient.Address != "" {
			RemoveIpFromAllocatedIpMap(network, extClient.Address)
		}
		if extClient.Address6 != "" {
			RemoveIpFromAllocatedIpMap(network, extClient.Address6)
		}
		deleteExtClientFromCache(key)
	}
	go RemoveNodeFromAclPolicy(extClient.ConvertToStaticNode())
	return nil
}

// DeleteExtClientAndCleanup - deletes an existing ext client and update ACLs
func DeleteExtClientAndCleanup(extClient models.ExtClient) error {

	//delete extClient record
	err := DeleteExtClient(extClient.Network, extClient.ClientID)
	if err != nil {
		slog.Error("DeleteExtClientAndCleanup-remove extClient record: ", "Error", err.Error())
		return err
	}

	//update ACLs
	var networkAcls acls.ACLContainer
	networkAcls, err = networkAcls.Get(acls.ContainerID(extClient.Network))
	if err != nil {
		slog.Error("DeleteExtClientAndCleanup-update network acls: ", "Error", err.Error())
		return err
	}
	for objId := range networkAcls {
		delete(networkAcls[objId], acls.AclID(extClient.ClientID))
	}
	delete(networkAcls, acls.AclID(extClient.ClientID))
	if _, err = networkAcls.Save(acls.ContainerID(extClient.Network)); err != nil {
		slog.Error("DeleteExtClientAndCleanup-update network acls:", "Error", err.Error())
		return err
	}

	return nil
}

//TODO - enforce extclient-to-extclient on ingress gw
/* 1. fetch all non-user static nodes
a. check against each user node, if allowed add rule

*/

// GetNetworkExtClients - gets the ext clients of given network
func GetNetworkExtClients(network string) ([]models.ExtClient, error) {
	var extclients []models.ExtClient
	if servercfg.CacheEnabled() {
		allextclients := getAllExtClientsFromCache()
		if len(allextclients) != 0 {
			for _, extclient := range allextclients {
				if extclient.Network == network {
					extclients = append(extclients, extclient)
				}
			}
			return extclients, nil
		}
	}
	records, err := database.FetchRecords(database.EXT_CLIENT_TABLE_NAME)
	if err != nil {
		if database.IsEmptyRecord(err) {
			return extclients, nil
		}
		return extclients, err
	}
	for _, value := range records {
		var extclient models.ExtClient
		err = json.Unmarshal([]byte(value), &extclient)
		if err != nil {
			continue
		}
		key, err := GetRecordKey(extclient.ClientID, extclient.Network)
		if err == nil {
			if servercfg.CacheEnabled() {
				storeExtClientInCache(key, extclient)
			}
		}
		if extclient.Network == network {
			extclients = append(extclients, extclient)
		}
	}
	return extclients, err
}

// GetExtClient - gets a single ext client on a network
func GetExtClient(clientid string, network string) (models.ExtClient, error) {
	var extclient models.ExtClient
	key, err := GetRecordKey(clientid, network)
	if err != nil {
		return extclient, err
	}
	if servercfg.CacheEnabled() {
		if extclient, ok := getExtClientFromCache(key); ok {
			return extclient, nil
		}
	}
	data, err := database.FetchRecord(database.EXT_CLIENT_TABLE_NAME, key)
	if err != nil {
		return extclient, err
	}
	err = json.Unmarshal([]byte(data), &extclient)
	if servercfg.CacheEnabled() {
		storeExtClientInCache(key, extclient)
	}
	return extclient, err
}

// GetGwExtclients - return all ext clients attached to the passed gw id
func GetGwExtclients(nodeID, network string) []models.ExtClient {
	gwClients := []models.ExtClient{}
	clients, err := GetNetworkExtClients(network)
	if err != nil {
		return gwClients
	}
	for _, client := range clients {
		if client.IngressGatewayID == nodeID {
			gwClients = append(gwClients, client)
		}
	}
	return gwClients
}

// GetExtClient - gets a single ext client on a network
func GetExtClientByPubKey(publicKey string, network string) (*models.ExtClient, error) {
	netClients, err := GetNetworkExtClients(network)
	if err != nil {
		return nil, err
	}
	for i := range netClients {
		ec := netClients[i]
		if ec.PublicKey == publicKey {
			return &ec, nil
		}
	}

	return nil, fmt.Errorf("no client found")
}

// CreateExtClient - creates and saves an extclient
func CreateExtClient(extclient *models.ExtClient) error {
	// lock because we may need unique IPs and having it concurrent makes parallel calls result in same "unique" IPs
	addressLock.Lock()
	defer addressLock.Unlock()

	if len(extclient.PublicKey) == 0 {
		privateKey, publicKey, err := GenerateP256KeyPair()
		if err != nil {
			return err
		}
		// Serialize private key (32 bytes big-endian → base64) for storage
		privB64, serr := SerializeP256PrivateKey(privateKey)
		if serr != nil {
			return serr
		}
		extclient.PrivateKey = privB64
		extclient.PublicKey = publicKey
	} else if len(extclient.PrivateKey) == 0 && len(extclient.PublicKey) > 0 {
		extclient.PrivateKey = "[ENTER PRIVATE KEY]"
	}
	if extclient.ExtraAllowedIPs == nil {
		extclient.ExtraAllowedIPs = []string{}
	}

	parentNetwork, err := GetNetwork(extclient.Network)
	if err != nil {
		return err
	}
	if extclient.Address == "" {
		if parentNetwork.IsIPv4 == "yes" {
			newAddress, err := UniqueAddress(extclient.Network, true)
			if err != nil {
				return err
			}
			extclient.Address = newAddress.String()
		}
	}

	if extclient.Address6 == "" {
		if parentNetwork.IsIPv6 == "yes" {
			addr6, err := UniqueAddress6(extclient.Network, true)
			if err != nil {
				return err
			}
			extclient.Address6 = addr6.String()
		}
	}

	if extclient.ClientID == "" {
		extclient.ClientID, err = GenerateNodeName(extclient.Network)
		if err != nil {
			return err
		}
	}

	extclient.LastModified = time.Now().Unix()
	return SaveExtClient(extclient)
}

// GenerateNodeName - generates a random node name
func GenerateNodeName(network string) (string, error) {
	seed := time.Now().UTC().UnixNano()
	nameGenerator := namegenerator.NewNameGenerator(seed)
	var name string
	cnt := 0
	for {
		if cnt > 10 {
			return "", errors.New("couldn't generate random name, try again")
		}
		cnt += 1
		name = nameGenerator.Generate()
		if len(name) > 15 {
			continue
		}
		_, err := GetExtClient(name, network)
		if err == nil {
			// config exists with same name
			continue
		}
		break
	}
	return name, nil
}

// SaveExtClient - saves an ext client to database
func SaveExtClient(extclient *models.ExtClient) error {
	key, err := GetRecordKey(extclient.ClientID, extclient.Network)
	if err != nil {
		return err
	}
	data, err := json.Marshal(&extclient)
	if err != nil {
		return err
	}
	if err = database.Insert(key, string(data), database.EXT_CLIENT_TABLE_NAME); err != nil {
		return err
	}
	if servercfg.CacheEnabled() {
		storeExtClientInCache(key, *extclient)
		if _, ok := allocatedIpMap[extclient.Network]; ok {
			if extclient.Address != "" {
				AddIpToAllocatedIpMap(extclient.Network, net.ParseIP(extclient.Address))
			}
			if extclient.Address6 != "" {
				AddIpToAllocatedIpMap(extclient.Network, net.ParseIP(extclient.Address6))
			}
		}
	}

	return SetNetworkNodesLastModified(extclient.Network)
}

// UpdateExtClient - updates an ext client with new values
func UpdateExtClient(old *models.ExtClient, update *models.CustomExtClient) models.ExtClient {
	new := *old
	new.ClientID = update.ClientID
	if update.PublicKey != "" && old.PublicKey != update.PublicKey {
		new.PublicKey = update.PublicKey
	}
	if update.DNS != old.DNS {
		new.DNS = update.DNS
	}
	if update.Enabled != old.Enabled {
		new.Enabled = update.Enabled
	}
	new.ExtraAllowedIPs = update.ExtraAllowedIPs
	if update.DeniedACLs != nil && !reflect.DeepEqual(old.DeniedACLs, update.DeniedACLs) {
		new.DeniedACLs = update.DeniedACLs
	}
	// replace any \r\n with \n in postup and postdown from HTTP request
	new.PostUp = strings.Replace(update.PostUp, "\r\n", "\n", -1)
	new.PostDown = strings.Replace(update.PostDown, "\r\n", "\n", -1)
	new.Tags = update.Tags
	return new
}

// GetExtClientsByID - gets the clients of attached gateway
func GetExtClientsByID(nodeid, network string) ([]models.ExtClient, error) {
	var result []models.ExtClient
	currentClients, err := GetNetworkExtClients(network)
	if err != nil {
		return result, err
	}
	for i := range currentClients {
		if currentClients[i].IngressGatewayID == nodeid {
			result = append(result, currentClients[i])
		}
	}
	return result, nil
}

// GetAllExtClients - gets all ext clients from DB
func GetAllExtClients() ([]models.ExtClient, error) {
	var clients = []models.ExtClient{}
	currentNetworks, err := GetNetworks()
	if err != nil && database.IsEmptyRecord(err) {
		return clients, nil
	} else if err != nil {
		return clients, err
	}

	for i := range currentNetworks {
		netName := currentNetworks[i].NetID
		netClients, err := GetNetworkExtClients(netName)
		if err != nil {
			continue
		}
		clients = append(clients, netClients...)
	}

	return clients, nil
}

// GetAllExtClientsWithStatus - returns all external clients with
// given status.
func GetAllExtClientsWithStatus(status models.NodeStatus) ([]models.ExtClient, error) {
	extClients, err := GetAllExtClients()
	if err != nil {
		return nil, err
	}

	var validExtClients []models.ExtClient
	for _, extClient := range extClients {
		node := extClient.ConvertToStaticNode()
		GetNodeCheckInStatus(&node, false)

		if node.Status == status {
			validExtClients = append(validExtClients, extClient)
		}
	}

	return validExtClients, nil
}

// ToggleExtClientConnectivity - enables or disables an ext client
func ToggleExtClientConnectivity(client *models.ExtClient, enable bool) (models.ExtClient, error) {
	update := models.CustomExtClient{
		Enabled:              enable,
		ClientID:             client.ClientID,
		PublicKey:            client.PublicKey,
		DNS:                  client.DNS,
		ExtraAllowedIPs:      client.ExtraAllowedIPs,
		DeniedACLs:           client.DeniedACLs,
		RemoteAccessClientID: client.RemoteAccessClientID,
	}

	// update in DB
	newClient := UpdateExtClient(client, &update)
	if err := DeleteExtClient(client.Network, client.ClientID); err != nil {
		slog.Error("failed to delete ext client during update", "id", client.ClientID, "network", client.Network, "error", err)
		return newClient, err
	}
	if err := SaveExtClient(&newClient); err != nil {
		slog.Error("failed to save updated ext client during update", "id", newClient.ClientID, "network", newClient.Network, "error", err)
		return newClient, err
	}

	return newClient, nil
}

// Sort a slice of net.IP addresses
func sortIPs(ips []net.IP) {
	sort.Slice(ips, func(i, j int) bool {
		ip1, ip2 := ips[i].To16(), ips[j].To16()
		return string(ip1) < string(ip2) // Compare as byte slices
	})
}

func GetStaticNodeIps(node models.Node) (ips []net.IP) {
	defer func() {
		sortIPs(ips)
	}()
	defaultUserPolicy, _ := GetDefaultPolicy(models.NetworkID(node.Network), models.UserPolicy)
	defaultDevicePolicy, _ := GetDefaultPolicy(models.NetworkID(node.Network), models.DevicePolicy)

	extclients := GetStaticNodesByNetwork(models.NetworkID(node.Network), false)
	for _, extclient := range extclients {
		if extclient.IsUserNode && defaultUserPolicy.Enabled {
			continue
		}
		if !extclient.IsUserNode && defaultDevicePolicy.Enabled {
			continue
		}
		if extclient.StaticNode.Address != "" {
			ips = append(ips, extclient.StaticNode.AddressIPNet4().IP)
		}
		if extclient.StaticNode.Address6 != "" {
			ips = append(ips, extclient.StaticNode.AddressIPNet6().IP)
		}
	}
	return
}

func getFwRulesForNodeAndPeerOnGw(node, peer models.Node, allowedPolicies []models.Acl) (rules []models.FwRule) {

	for _, policy := range allowedPolicies {
		// if static peer dst rule not for ingress node -> skip
		if node.Address.IP != nil {
			rules = append(rules, models.FwRule{
				SrcIP: net.IPNet{
					IP:   node.Address.IP,
					Mask: net.CIDRMask(32, 32),
				},
				DstIP: net.IPNet{
					IP:   peer.Address.IP,
					Mask: net.CIDRMask(32, 32),
				},
				AllowedProtocol: policy.Proto,
				AllowedPorts:    policy.Port,
				Allow:           true,
			})
		}

		if node.Address6.IP != nil {
			rules = append(rules, models.FwRule{
				SrcIP: net.IPNet{
					IP:   node.Address6.IP,
					Mask: net.CIDRMask(128, 128),
				},
				DstIP: net.IPNet{
					IP:   peer.Address6.IP,
					Mask: net.CIDRMask(128, 128),
				},
				AllowedProtocol: policy.Proto,
				AllowedPorts:    policy.Port,
				Allow:           true,
			})
		}
		if policy.AllowedDirection == models.TrafficDirectionBi {
			if node.Address.IP != nil {
				rules = append(rules, models.FwRule{
					SrcIP: net.IPNet{
						IP:   peer.Address.IP,
						Mask: net.CIDRMask(32, 32),
					},
					DstIP: net.IPNet{
						IP:   node.Address.IP,
						Mask: net.CIDRMask(32, 32),
					},
					AllowedProtocol: policy.Proto,
					AllowedPorts:    policy.Port,
					Allow:           true,
				})
			}

			if node.Address6.IP != nil {
				rules = append(rules, models.FwRule{
					SrcIP: net.IPNet{
						IP:   peer.Address6.IP,
						Mask: net.CIDRMask(128, 128),
					},
					DstIP: net.IPNet{
						IP:   node.Address6.IP,
						Mask: net.CIDRMask(128, 128),
					},
					AllowedProtocol: policy.Proto,
					AllowedPorts:    policy.Port,
					Allow:           true,
				})
			}
		}
		if len(node.StaticNode.ExtraAllowedIPs) > 0 {
			for _, additionalAllowedIPNet := range node.StaticNode.ExtraAllowedIPs {
				_, ipNet, err := net.ParseCIDR(additionalAllowedIPNet)
				if err != nil {
					continue
				}
				if ipNet.IP.To4() != nil && peer.Address.IP != nil {
					rules = append(rules, models.FwRule{
						SrcIP: net.IPNet{
							IP:   peer.Address.IP,
							Mask: net.CIDRMask(32, 32),
						},
						DstIP: *ipNet,
						Allow: true,
					})
				} else if peer.Address6.IP != nil {
					rules = append(rules, models.FwRule{
						SrcIP: net.IPNet{
							IP:   peer.Address6.IP,
							Mask: net.CIDRMask(128, 128),
						},
						DstIP: *ipNet,
						Allow: true,
					})
				}

			}

		}
		if len(peer.StaticNode.ExtraAllowedIPs) > 0 {
			for _, additionalAllowedIPNet := range peer.StaticNode.ExtraAllowedIPs {
				_, ipNet, err := net.ParseCIDR(additionalAllowedIPNet)
				if err != nil {
					continue
				}
				if ipNet.IP.To4() != nil && node.Address.IP != nil {
					rules = append(rules, models.FwRule{
						SrcIP: net.IPNet{
							IP:   node.Address.IP,
							Mask: net.CIDRMask(32, 32),
						},
						DstIP: *ipNet,
						Allow: true,
					})
				} else if node.Address6.IP != nil {
					rules = append(rules, models.FwRule{
						SrcIP: net.IPNet{
							IP:   node.Address6.IP,
							Mask: net.CIDRMask(128, 128),
						},
						DstIP: *ipNet,
						Allow: true,
					})
				}

			}

		}

		// add egress range rules
		for _, dstI := range policy.Dst {
			if dstI.ID == models.EgressRange {
				ip, cidr, err := net.ParseCIDR(dstI.Value)
				if err == nil {
					if ip.To4() != nil {
						if node.Address.IP != nil {
							rules = append(rules, models.FwRule{
								SrcIP: net.IPNet{
									IP:   node.Address.IP,
									Mask: net.CIDRMask(32, 32),
								},
								DstIP:           *cidr,
								AllowedProtocol: policy.Proto,
								AllowedPorts:    policy.Port,
								Allow:           true,
							})
						}
					} else {
						if node.Address6.IP != nil {
							rules = append(rules, models.FwRule{
								SrcIP: net.IPNet{
									IP:   node.Address6.IP,
									Mask: net.CIDRMask(128, 128),
								},
								DstIP:           *cidr,
								AllowedProtocol: policy.Proto,
								AllowedPorts:    policy.Port,
								Allow:           true,
							})
						}
					}

				}
			}
		}
	}

	return
}

func getFwRulesForUserNodesOnGw(node models.Node, nodes []models.Node) (rules []models.FwRule) {
	defaultUserPolicy, _ := GetDefaultPolicy(models.NetworkID(node.Network), models.UserPolicy)
	userNodes := GetStaticUserNodesByNetwork(models.NetworkID(node.Network))
	for _, userNodeI := range userNodes {
		for _, peer := range nodes {
			if peer.IsUserNode {
				continue
			}

			if ok, allowedPolicies := IsUserAllowedToCommunicate(userNodeI.StaticNode.OwnerID, peer); ok {
				if peer.IsStatic {
					peer = peer.StaticNode.ConvertToStaticNode()
				}
				if !defaultUserPolicy.Enabled {
					for _, policy := range allowedPolicies {
						if userNodeI.StaticNode.Address != "" {
							rules = append(rules, models.FwRule{
								SrcIP: userNodeI.StaticNode.AddressIPNet4(),
								DstIP: net.IPNet{
									IP:   peer.Address.IP,
									Mask: net.CIDRMask(32, 32),
								},
								AllowedProtocol: policy.Proto,
								AllowedPorts:    policy.Port,
								Allow:           true,
							})
						}
						if userNodeI.StaticNode.Address6 != "" {
							rules = append(rules, models.FwRule{
								SrcIP: userNodeI.StaticNode.AddressIPNet6(),
								DstIP: net.IPNet{
									IP:   peer.Address6.IP,
									Mask: net.CIDRMask(128, 128),
								},
								AllowedProtocol: policy.Proto,
								AllowedPorts:    policy.Port,
								Allow:           true,
							})
						}

						// add egress ranges
						for _, dstI := range policy.Dst {
							if dstI.ID == models.EgressRange {
								ip, cidr, err := net.ParseCIDR(dstI.Value)
								if err == nil {
									if ip.To4() != nil && userNodeI.StaticNode.Address != "" {
										rules = append(rules, models.FwRule{
											SrcIP:           userNodeI.StaticNode.AddressIPNet4(),
											DstIP:           *cidr,
											AllowedProtocol: policy.Proto,
											AllowedPorts:    policy.Port,
											Allow:           true,
										})
									} else if ip.To16() != nil && userNodeI.StaticNode.Address6 != "" {
										rules = append(rules, models.FwRule{
											SrcIP:           userNodeI.StaticNode.AddressIPNet6(),
											DstIP:           *cidr,
											AllowedProtocol: policy.Proto,
											AllowedPorts:    policy.Port,
											Allow:           true,
										})
									}
								}
							}
						}

					}
				}

			}
		}
	}
	return
}

func GetFwRulesOnIngressGateway(node models.Node) (rules []models.FwRule) {
	// fetch user access to static clients via policies
	defer func() {
		sort.Slice(rules, func(i, j int) bool {
			if !rules[i].SrcIP.IP.Equal(rules[j].SrcIP.IP) {
				return string(rules[i].SrcIP.IP.To16()) < string(rules[j].SrcIP.IP.To16())
			}
			return string(rules[i].DstIP.IP.To16()) < string(rules[j].DstIP.IP.To16())
		})
	}()
	defaultDevicePolicy, _ := GetDefaultPolicy(models.NetworkID(node.Network), models.DevicePolicy)
	nodes, _ := GetNetworkNodes(node.Network)
	nodes = append(nodes, GetStaticNodesByNetwork(models.NetworkID(node.Network), true)...)
	rules = getFwRulesForUserNodesOnGw(node, nodes)
	if defaultDevicePolicy.Enabled {
		return
	}
	for _, nodeI := range nodes {
		if !nodeI.IsStatic || nodeI.IsUserNode {
			continue
		}
		// if nodeI.StaticNode.IngressGatewayID != node.ID.String() {
		// 	continue
		// }
		for _, peer := range nodes {
			if peer.StaticNode.ClientID == nodeI.StaticNode.ClientID || peer.IsUserNode {
				continue
			}
			if nodeI.StaticNode.IngressGatewayID != node.ID.String() &&
				((!peer.IsStatic && peer.ID.String() != node.ID.String()) ||
					(peer.IsStatic && peer.StaticNode.IngressGatewayID != node.ID.String())) {
				continue
			}
			if peer.IsStatic {
				peer = peer.StaticNode.ConvertToStaticNode()
			}
			var allowedPolicies1 []models.Acl
			var ok bool
			if ok, allowedPolicies1 = IsNodeAllowedToCommunicateV1(nodeI.StaticNode.ConvertToStaticNode(), peer, true); ok {
				rules = append(rules, getFwRulesForNodeAndPeerOnGw(nodeI.StaticNode.ConvertToStaticNode(), peer, allowedPolicies1)...)
			}
			if ok, allowedPolicies2 := IsNodeAllowedToCommunicateV1(peer, nodeI.StaticNode.ConvertToStaticNode(), true); ok {
				rules = append(rules,
					getFwRulesForNodeAndPeerOnGw(peer, nodeI.StaticNode.ConvertToStaticNode(),
						GetUniquePolicies(allowedPolicies1, allowedPolicies2))...)
			}
		}
	}
	return
}

func GetUniquePolicies(policies1, policies2 []models.Acl) []models.Acl {
	policies1Map := make(map[string]struct{})
	for _, policy1I := range policies1 {
		policies1Map[policy1I.ID] = struct{}{}
	}
	for i := len(policies2) - 1; i >= 0; i-- {
		if _, ok := policies1Map[policies2[i].ID]; ok {
			policies2 = append(policies2[:i], policies2[i+1:]...)
		}
	}
	return policies2
}

func GetExtPeers(node, peer *models.Node) ([]models.FIPSPeerConfig, []models.IDandAddr, []models.EgressNetworkRoutes, error) {
	var peers []models.FIPSPeerConfig
	var idsAndAddr []models.IDandAddr
	var egressRoutes []models.EgressNetworkRoutes
	extPeers, err := GetNetworkExtClients(node.Network)
	if err != nil {
		return peers, idsAndAddr, egressRoutes, err
	}
	host, err := GetHost(node.HostID.String())
	if err != nil {
		return peers, idsAndAddr, egressRoutes, err
	}
	for _, extPeer := range extPeers {
		extPeer := extPeer
		if !IsClientNodeAllowed(&extPeer, peer.ID.String()) {
			continue
		}
		if extPeer.RemoteAccessClientID == "" {
			if ok := IsPeerAllowed(extPeer.ConvertToStaticNode(), *peer, true); !ok {
				continue
			}
		} else {
			if ok, _ := IsUserAllowedToCommunicate(extPeer.OwnerID, *peer); !ok {
				continue
			}
		}

		if err := ValidatePublicKey(extPeer.PublicKey); err != nil {
			logger.Log(1, "error parsing ext pub key:", err.Error())
			continue
		}

		if host.PublicKey == extPeer.PublicKey ||
			extPeer.IngressGatewayID != node.ID.String() || !extPeer.Enabled {
			continue
		}

		var allowedips []net.IPNet
		var peer models.FIPSPeerConfig
		if extPeer.Address != "" {
			var peeraddr = net.IPNet{
				IP:   net.ParseIP(extPeer.Address),
				Mask: net.CIDRMask(32, 32),
			}
			if peeraddr.IP != nil && peeraddr.Mask != nil {
				allowedips = append(allowedips, peeraddr)
			}
		}

		if extPeer.Address6 != "" {
			var addr6 = net.IPNet{
				IP:   net.ParseIP(extPeer.Address6),
				Mask: net.CIDRMask(128, 128),
			}
			if addr6.IP != nil && addr6.Mask != nil {
				allowedips = append(allowedips, addr6)
			}
		}
		for _, extraAllowedIP := range extPeer.ExtraAllowedIPs {
			_, cidr, err := net.ParseCIDR(extraAllowedIP)
			if err == nil {
				allowedips = append(allowedips, *cidr)
			}
		}
		egressRoutes = append(egressRoutes, getExtPeerEgressRoute(*node, extPeer)...)
		primaryAddr := extPeer.Address
		if primaryAddr == "" {
			primaryAddr = extPeer.Address6
		}
		var allowedIPsStrings []string
		for _, ipNet := range allowedips {
			allowedIPsStrings = append(allowedIPsStrings, ipNet.String())
		}
		peer = models.FIPSPeerConfig{
			PublicKey:         extPeer.PublicKey,
			ReplaceAllowedIPs: true,
			AllowedIPs:        allowedIPsStrings,
		}
		peers = append(peers, peer)
		idsAndAddr = append(idsAndAddr, models.IDandAddr{
			ID:          extPeer.PublicKey,
			Name:        extPeer.ClientID,
			Address:     primaryAddr,
			IsExtClient: true,
		})
	}
	return peers, idsAndAddr, egressRoutes, nil

}

func getExtPeerEgressRoute(node models.Node, extPeer models.ExtClient) (egressRoutes []models.EgressNetworkRoutes) {
	r := models.EgressNetworkRoutes{
		PeerKey:       extPeer.PublicKey,
		EgressGwAddr:  extPeer.AddressIPNet4(),
		EgressGwAddr6: extPeer.AddressIPNet6(),
		NodeAddr:      node.Address,
		NodeAddr6:     node.Address6,
		EgressRanges:  extPeer.ExtraAllowedIPs,
	}
	for _, extraAllowedIP := range extPeer.ExtraAllowedIPs {
		r.EgressRangesWithMetric = append(r.EgressRangesWithMetric, models.EgressRangeMetric{
			Network:     extraAllowedIP,
			RouteMetric: 256,
		})
	}
	egressRoutes = append(egressRoutes, r)
	return
}

func getExtpeerEgressRanges(node models.Node) (ranges, ranges6 []net.IPNet) {
	extPeers, err := GetNetworkExtClients(node.Network)
	if err != nil {
		return
	}
	for _, extPeer := range extPeers {
		if len(extPeer.ExtraAllowedIPs) == 0 {
			continue
		}
		if ok, _ := IsNodeAllowedToCommunicateV1(extPeer.ConvertToStaticNode(), node, true); !ok {
			continue
		}
		for _, allowedRange := range extPeer.ExtraAllowedIPs {
			_, ipnet, err := net.ParseCIDR(allowedRange)
			if err == nil {
				if ipnet.IP.To4() != nil {
					ranges = append(ranges, *ipnet)
				} else {
					ranges6 = append(ranges6, *ipnet)
				}

			}
		}
	}
	return
}

func getExtpeersExtraRoutes(node models.Node) (egressRoutes []models.EgressNetworkRoutes) {
	extPeers, err := GetNetworkExtClients(node.Network)
	if err != nil {
		return
	}
	for _, extPeer := range extPeers {
		if len(extPeer.ExtraAllowedIPs) == 0 {
			continue
		}
		if ok, _ := IsNodeAllowedToCommunicateV1(extPeer.ConvertToStaticNode(), node, true); !ok {
			continue
		}
		egressRoutes = append(egressRoutes, getExtPeerEgressRoute(node, extPeer)...)
	}
	return
}

func GetExtclientAllowedIPs(client models.ExtClient) (allowedIPs []string) {
	gwnode, err := GetNodeByID(client.IngressGatewayID)
	if err != nil {
		logger.Log(0,
			fmt.Sprintf("failed to get ingress gateway node [%s] info: %v", client.IngressGatewayID, err))
		return
	}

	network, err := GetParentNetwork(client.Network)
	if err != nil {
		logger.Log(1, "Could not retrieve Ingress Gateway Network", client.Network)
		return
	}
	if IsInternetGw(gwnode) {
		egressrange := "0.0.0.0/0"
		if gwnode.Address6.IP != nil && client.Address6 != "" {
			egressrange += "," + "::/0"
		}
		allowedIPs = []string{egressrange}
	} else {
		allowedIPs = []string{network.AddressRange}

		if network.AddressRange6 != "" {
			allowedIPs = append(allowedIPs, network.AddressRange6)
		}
		if egressGatewayRanges, err := GetEgressRangesOnNetwork(&client); err == nil {
			allowedIPs = append(allowedIPs, egressGatewayRanges...)
		}
	}
	return
}

func GetStaticUserNodesByNetwork(network models.NetworkID) (staticNode []models.Node) {
	extClients, err := GetAllExtClients()
	if err != nil {
		return
	}
	for _, extI := range extClients {
		if extI.Network == network.String() {
			if extI.RemoteAccessClientID != "" {
				n := extI.ConvertToStaticNode()
				staticNode = append(staticNode, n)
			}
		}
	}
	return
}

func GetStaticNodesByNetwork(network models.NetworkID, onlyWg bool) (staticNode []models.Node) {
	extClients, err := GetAllExtClients()
	if err != nil {
		return
	}
	SortExtClient(extClients[:])
	for _, extI := range extClients {
		if extI.Network == network.String() {
			if onlyWg && extI.RemoteAccessClientID != "" {
				continue
			}
			n := models.Node{
				IsStatic:   true,
				StaticNode: extI,
				IsUserNode: extI.RemoteAccessClientID != "",
			}
			staticNode = append(staticNode, n)
		}
	}

	return
}

func GetStaticNodesByGw(gwNode models.Node) (staticNode []models.Node) {
	extClients, err := GetAllExtClients()
	if err != nil {
		return
	}
	for _, extI := range extClients {
		if extI.IngressGatewayID == gwNode.ID.String() {
			n := models.Node{
				IsStatic:   true,
				StaticNode: extI,
				IsUserNode: extI.RemoteAccessClientID != "",
			}
			staticNode = append(staticNode, n)
		}
	}
	return
}

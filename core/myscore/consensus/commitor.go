package consensus

import (
	"WuKong/core"
	"WuKong/crypto"
	"WuKong/logger"
	"WuKong/mempool"
	"WuKong/store"
	"sync"
)

type pattern int

const (
	unjudge pattern = iota
	toskip
	undecide
	toCommit
	mvbaing
)

type LocalDAG struct {
	store        *store.Store
	committee    core.Committee
	muBlock      *sync.RWMutex
	blockDigests map[crypto.Digest]core.NodeID // store hash of block that has received
	muDAG        *sync.RWMutex
	localDAG     map[int]map[core.NodeID]crypto.Digest // local DAG
	edgesDAG     map[int]map[core.NodeID]map[crypto.Digest]core.NodeID
	muCert       *sync.RWMutex
	iscertDAG    map[int]map[core.NodeID]pattern //proposer pattern
}

func NewLocalDAG(store *store.Store, committee core.Committee) *LocalDAG {
	return &LocalDAG{
		muBlock:      &sync.RWMutex{},
		muDAG:        &sync.RWMutex{},
		muCert:       &sync.RWMutex{},
		blockDigests: make(map[crypto.Digest]core.NodeID),
		localDAG:     make(map[int]map[core.NodeID]crypto.Digest),
		edgesDAG:     make(map[int]map[core.NodeID]map[crypto.Digest]core.NodeID),
		iscertDAG:    make(map[int]map[core.NodeID]pattern),
		store:        store,
		committee:    committee,
	}
}

// IsReceived: digests is received ?
func (local *LocalDAG) IsReceived(digests ...crypto.Digest) (bool, []crypto.Digest) {
	local.muBlock.RLock()
	defer local.muBlock.RUnlock()

	var miss []crypto.Digest
	var flag bool = true
	for _, d := range digests {
		if _, ok := local.blockDigests[d]; !ok {
			miss = append(miss, d)
			flag = false
		}
	}

	return flag, miss
}

func (local *LocalDAG) ReceiveBlock(round int, node core.NodeID, digest crypto.Digest, references map[crypto.Digest]core.NodeID) {
	local.muBlock.RLock()
	if _, ok := local.blockDigests[digest]; ok {
		local.muBlock.RUnlock()
		return
	}
	local.muBlock.RUnlock()

	logger.Debug.Printf("ReceiveBlock: round=%d node=%d ", round, node)
	local.muBlock.Lock()
	local.blockDigests[digest] = node
	local.muBlock.Unlock()

	local.muDAG.Lock()

	vslot, ok := local.localDAG[round]
	if !ok {
		vslot = make(map[core.NodeID]crypto.Digest)
		local.localDAG[round] = vslot
	}

	eslot, ok := local.edgesDAG[round]
	if !ok {
		eslot = make(map[core.NodeID]map[crypto.Digest]core.NodeID)
		local.edgesDAG[round] = eslot
	}

	certslot, ok := local.iscertDAG[round]
	if !ok {
		certslot = make(map[core.NodeID]pattern)
		local.iscertDAG[round] = certslot
	}

	vslot[node] = digest
	eslot[node] = references
	certslot[node] = unjudge
	local.muDAG.Unlock()
}

func (local *LocalDAG) GetRoundReceivedBlockNums(round int) (nums int) {
	local.muDAG.RLock()
	defer local.muDAG.RUnlock()

	nums = len(local.localDAG[round])

	return
}

func (local *LocalDAG) GetReceivedBlock(round int, node core.NodeID) (crypto.Digest, bool) {
	local.muDAG.RLock()
	defer local.muDAG.RUnlock()
	if slot, ok := local.localDAG[round]; ok {
		d, ok := slot[node]
		return d, ok
	}
	return crypto.Digest{}, false
}

func (local *LocalDAG) GetReceivedBlockReference(round int, node core.NodeID) (map[crypto.Digest]core.NodeID, bool) {
	local.muDAG.RLock()
	defer local.muDAG.RUnlock()
	if slot, ok := local.edgesDAG[round]; ok {
		reference, ok := slot[node]
		if ok {
			return reference, ok
		}
	}
	return nil, false
}

func (local *LocalDAG) GetRoundReceivedBlock(round int) map[core.NodeID]crypto.Digest {
	local.muDAG.RLock()
	defer local.muDAG.RUnlock()

	original := local.localDAG[round]

	copied := make(map[core.NodeID]crypto.Digest, len(original))
	for k, v := range original {
		copied[k] = v
	}

	return copied
}

func (local *LocalDAG) GetRoundReferrences(round int) map[core.NodeID]map[crypto.Digest]core.NodeID {
	local.muDAG.RLock()
	defer local.muDAG.RUnlock()

	original := local.edgesDAG[round]

	copied := make(map[core.NodeID]map[crypto.Digest]core.NodeID, len(original))
	for k, v := range original {
		copied[k] = v
	}

	return copied
}

func (local *LocalDAG) GetRoundReceivedBlocks(round int) (references map[crypto.Digest]core.NodeID) {
	local.muDAG.RLock()
	defer local.muDAG.RUnlock()

	blocks := local.localDAG[round]

	references = make(map[crypto.Digest]core.NodeID)
	for id, digest := range blocks {
		references[digest] = id
	}
	return references
}

func (local *LocalDAG) GetRoundFplusOneReceivedBlocks(round int) (references map[crypto.Digest]core.NodeID) {
	local.muDAG.RLock()
	defer local.muDAG.RUnlock()

	blocks := local.localDAG[round]
	var i int = 0
	references = make(map[crypto.Digest]core.NodeID)
	for id, digest := range blocks {
		if i < local.committee.LowThreshold() {
			references[digest] = id
			i++
		}
	}
	return references
}

func (local *LocalDAG) GetsMVBAValue(round int) []crypto.Digest {

	references := local.GetRoundReceivedBlock(round)

	var sMVBAValue []crypto.Digest

	for i := 0; i < local.committee.Size(); i++ {
		digest, ok := references[core.NodeID(i)]
		if !ok {
			sMVBAValue = append(sMVBAValue, crypto.Digest{})
		} else {
			sMVBAValue = append(sMVBAValue, digest)
		}
	}

	return sMVBAValue
}

// judge if bvote refer to bproposer
func (local *LocalDAG) isVote(Bproposer *Block, Bvote *Block) bool {
	id := Bproposer.Author
	r := Bproposer.Round

	return local.supportedblock(Bvote, id, r) == Bproposer.Hash()

}

func (local *LocalDAG) supportedblock(b *Block, id core.NodeID, r int) crypto.Digest {

	digests := b.Reference

	if r >= b.Round {
		return crypto.Digest{}
	}
	for key, value := range digests {
		if value == id && r == b.Round-1 {
			return key
		}

	}
	return crypto.Digest{}
}

func (local *LocalDAG) isCert(Bproposer *Block, BcertRef map[crypto.Digest]core.NodeID) bool {

	var voteCount int = 0
	for key := range BcertRef {
		if bvote, err := getBlock(local.store, key); err != nil {
			logger.Warn.Println(err)
			continue
		} else {
			if local.isVote(Bproposer, bvote) {
				voteCount++
			}
		}
	}

	return voteCount >= local.committee.HightThreshold()

}

func (local *LocalDAG) GetVotingBlocks(round int) map[core.NodeID]crypto.Digest {

	return local.GetRoundReceivedBlock(round)

}

func (local *LocalDAG) GetDecisonBlocks(b *Block) map[core.NodeID]crypto.Digest {

	return local.GetRoundReceivedBlock(b.Round + 2)

}

func (local *LocalDAG) skippedProposer(id core.NodeID, round int) bool {
	var res int = 0

	blocks := local.GetVotingBlocks(round + 1)
	for _, digest := range blocks {
		if block, err := getBlock(local.store, digest); err != nil {
			logger.Warn.Println(err)
		} else {
			if !containsValue(block.Reference, id) {
				res++
			}
		}
	}

	return res >= local.committee.HightThreshold()
}

func containsValue(m map[crypto.Digest]core.NodeID, target core.NodeID) bool {
	for _, v := range m {
		if v == target {
			return true
		}
	}
	return false
}

func (local *LocalDAG) committedProposer(b *Block) (bool, int) {
	var certCount int = 0

	references := local.GetRoundReferrences(b.Round + 2)
	for _, ref := range references {

		if local.isCert(b, ref) {
			certCount++
		}

	}
	return certCount >= local.committee.HightThreshold(), certCount
}

type ABAid struct {
	round      int
	slot       core.NodeID
	flag       uint8
	localstate uint8
	abablock   crypto.Digest
	certblock  crypto.Digest
}

type SMVBAid struct {
	epoch      int
	blockhashs []crypto.Digest
}

type commitMsg struct {
	round  int
	node   core.NodeID
	ptern  pattern
	digest crypto.Digest
}

type Commitor struct {
	commitChannel chan<- *Block
	localDAG      *LocalDAG
	commitBlocks  map[crypto.Digest]struct{}
	commitPayload map[crypto.Digest]struct{}
	notify        chan struct{}
	notifycommit  chan *commitMsg
	inner         chan crypto.Digest
	store         *store.Store
	parameter     core.Parameters

	//mempool    *mempool.Mempool
	connectChannel  chan core.Message
	pendingPayloads map[crypto.Digest]chan struct{} // digest -> waiting channel
	muPending       *sync.RWMutex
	notifyPload     chan crypto.Digest

	startABA    chan<- *ABAid
	commitRound int
	commitNode  core.NodeID
	judinground int
	judingnode  core.NodeID
	mucDAG      *sync.RWMutex
	commitDAG   map[int]map[core.NodeID]crypto.Digest
	certDAG     map[int]map[core.NodeID]pattern

	//sMVBA
	sMVBAStart chan *SMVBAid
}

func NewCommitor(localDAG *LocalDAG, store *store.Store, commitChannel chan<- *Block, startABA chan<- *ABAid, mc chan core.Message, notify chan crypto.Digest, smvba chan *SMVBAid, p core.Parameters) *Commitor {
	c := &Commitor{
		mucDAG:        &sync.RWMutex{},
		localDAG:      localDAG,
		commitChannel: commitChannel,
		commitBlocks:  make(map[crypto.Digest]struct{}),
		commitPayload: make(map[crypto.Digest]struct{}),
		notify:        make(chan struct{}, 100),
		commitDAG:     make(map[int]map[core.NodeID]crypto.Digest),
		certDAG:       make(map[int]map[core.NodeID]pattern),
		notifycommit:  make(chan *commitMsg, 1000),
		store:         store,
		parameter:     p,

		commitRound: 0,
		commitNode:  core.NodeID(p.StartProposer),
		judinground: 0,
		judingnode:  core.NodeID(p.StartProposer),

		connectChannel: mc,
		//mempool:       mempool,
		pendingPayloads: make(map[crypto.Digest]chan struct{}),
		muPending:       &sync.RWMutex{},
		notifyPload:     notify,

		inner:    make(chan crypto.Digest, 100),
		startABA: startABA,

		sMVBAStart: smvba,
	}
	go c.run()
	return c
}

func (c *Commitor) waitForPayload(digest crypto.Digest) {
	c.muPending.Lock()
	ch, ok := c.pendingPayloads[digest]
	if !ok {
		ch = make(chan struct{}, 1)
		c.pendingPayloads[digest] = ch
	}
	c.muPending.Unlock()
	// 阻塞等待直到 payload 被收到并写入此通道
	<-ch
	logger.Debug.Printf("channel receive \n")
	c.muPending.Lock()
	delete(c.pendingPayloads, digest)
	c.muPending.Unlock()

}

func (c *Commitor) run() {

	go func() {
		for digest := range c.inner {
			if block, err := getBlock(c.store, digest); err != nil {
				logger.Warn.Println(err)
			} else {
				if !block.Nil {

					for _, d := range block.PayLoads {
						if _, ok := c.commitPayload[d]; ok {
							continue
						}
						payload, err := GetPayload(c.store, d)
						if err != nil {
							logger.Debug.Printf("miss payload round %d node %d\n", block.Round, block.Author)
							//  1. 向网络请求缺失 payload

							msg := &mempool.VerifyBlockMsg{
								Proposer:           block.Author,
								Epoch:              int64(block.Round),
								Payloads:           block.PayLoads,
								ConsensusBlockHash: block.Hash(),
								Sender:             make(chan mempool.VerifyStatus),
							}

							c.connectChannel <- msg
							status := <-msg.Sender
							if status != mempool.OK {
								//  2. 等待 payload 补全（阻塞等待）

								c.waitForPayload(digest)
								logger.Debug.Printf("receive payload by verify \n")
							}
							payload, _ = GetPayload(c.store, d)
						}
						if payload.Batch.ID != -1 {
							logger.Info.Printf("commit batch %d \n", payload.Batch.ID)

						}
						c.commitPayload[d] = struct{}{}

					}

					c.commitChannel <- block

					logger.Info.Printf("commit Block round %d node %d \n", block.Round, block.Author)
					c.connectChannel <- &mempool.CleanBlockMsg{
						Digests: block.PayLoads,
					}

				}

			}
		}
	}()

	go func() {
		for m := range c.notifycommit {
			c.receivePattern(m)
		}
	}()
	go func() {
		for digest := range c.notifyPload {
			c.muPending.RLock()
			if ch, ok := c.pendingPayloads[digest]; ok {
				select {
				case ch <- struct{}{}: // 通知已经到达
				default: // 防止阻塞，如果已经有人写过了就跳过
				}
			}
			c.muPending.RUnlock()
		}
	}()
	for range c.notify {
		c.judgePattern()

	}
}

func (c *Commitor) ifLossLiveness(round int) bool {

	roundPattern := c.certDAG[round]

	if len(roundPattern) != c.parameter.EndProposer-c.parameter.StartProposer+1 {
		return false
	}
	for i := c.parameter.StartProposer; i < c.parameter.EndProposer+1; i++ {
		item := roundPattern[core.NodeID(i)]
		if item != toskip {
			return false
		}
	}
	return true
}

func (c *Commitor) judgePattern() {
	for {

		if c.localDAG.GetRoundReceivedBlockNums(c.judinground+1) >= c.localDAG.committee.HightThreshold() {
			if c.localDAG.skippedProposer(c.judingnode, c.judinground) {
				logger.Debug.Printf("judge round %d node %d toskip\n", c.judinground, c.judingnode)
				c.notifycommit <- &commitMsg{
					round:  c.judinground,
					node:   c.judingnode,
					ptern:  toskip,
					digest: crypto.Digest{},
				}

				c.advancedJudingPointer()

				continue
			} else if c.localDAG.GetRoundReceivedBlockNums(c.judinground+2) >= c.localDAG.committee.HightThreshold() {
				c.localDAG.muDAG.RLock()
				digest := c.localDAG.localDAG[c.judinground][c.judingnode]
				c.localDAG.muDAG.RUnlock()

				var certsNum int
				var ifCommit bool = false
				if block, err := getBlock(c.store, digest); err != nil {
					logger.Warn.Println(err)
				} else {
					flag, nums := c.localDAG.committedProposer(block)
					if flag {
						c.notifycommit <- &commitMsg{
							round:  c.judinground,
							node:   c.judingnode,
							ptern:  toCommit,
							digest: digest,
						}
						logger.Debug.Printf("judge round %d node %d  tocommit \n", c.judinground, c.judingnode)
						ifCommit = true
						c.advancedJudingPointer()
					}
					certsNum = nums
				}

				if !ifCommit {
					logger.Debug.Printf("undecided round %d node %d \n", c.judinground, c.judingnode)
					c.notifycommit <- &commitMsg{
						round:  c.judinground,
						node:   c.judingnode,
						ptern:  undecide,
						digest: crypto.Digest{},
					}
					if certsNum > 0 {
						c.startABA <- &ABAid{
							round:      c.judinground,
							slot:       c.judingnode,
							flag:       FLAG_YES,
							localstate: FLAG_YES,
							abablock:   digest,
							certblock:  crypto.Digest{},
						}
					} else {
						c.startABA <- &ABAid{
							round:      c.judinground,
							slot:       c.judingnode,
							flag:       FLAG_NO,
							localstate: FLAG_YES,
							abablock:   crypto.Digest{},
							certblock:  crypto.Digest{},
						}
					}
					c.advancedJudingPointer()
				}
			} else { //no 2f+1 decisionblocks
				break
			}
		} else { //no 2f+1 votingblocks
			break
		}

	}

}

// func (c *Commitor) tryToCommit() {

// }

func (c *Commitor) receivePattern(m *commitMsg) {
	c.mucDAG.Lock()
	defer c.mucDAG.Unlock()
	if _, ok := c.certDAG[m.round]; !ok {
		c.certDAG[m.round] = make(map[core.NodeID]pattern)
	}
	p, ok := c.certDAG[m.round][m.node]
	if !ok {
		c.certDAG[m.round][m.node] = m.ptern
	} else if p != toCommit && p != toskip {
		c.certDAG[m.round][m.node] = m.ptern
	}

	if m.ptern == toskip {
		if c.ifLossLiveness(m.round) {
			logger.Debug.Printf("lossliveness test")
			for ix := 0; ix < c.parameter.EndProposer+1; ix++ {
				c.certDAG[m.round][core.NodeID(ix)] = mvbaing
			}

			//modify commitPointer
			if c.commitRound < m.round {

			} else if c.commitRound == m.round {
				c.commitNode = core.NodeID(0)
				logger.Debug.Printf("modify commitpointer round %d node %d \n", c.commitRound, c.commitNode)
			} else if c.commitRound > m.round {
				c.commitRound = m.round
				c.commitNode = core.NodeID(0)
				logger.Debug.Printf("modify commitpointer round %d node %d \n", c.commitRound, c.commitNode)
			}
			value := c.localDAG.GetsMVBAValue(m.round)
			//start sMvba
			c.sMVBAStart <- &SMVBAid{
				epoch:      m.round,
				blockhashs: value,
			}
		}
	} else if m.ptern == toCommit {
		if _, ok := c.commitDAG[m.round]; !ok {
			c.commitDAG[m.round] = make(map[core.NodeID]crypto.Digest)
		}
		c.commitDAG[m.round][m.node] = m.digest
	}

	for {
		ptern, ok := c.certDAG[c.commitRound]

		if !ok {
			break
		} else {
			if ptern[c.commitNode] == toCommit {
				logger.Debug.Printf("commit leader round %d node %d \n", c.commitRound, c.commitNode)
				digest := c.commitDAG[c.commitRound][c.commitNode]
				if block, err := getBlock(c.store, digest); err != nil {
					logger.Warn.Println(err)
				} else {
					refs := block.Reference
					for ref := range refs {
						if _, ok := c.commitBlocks[ref]; !ok {

							c.commitBlocks[ref] = struct{}{} // commit flag
							c.inner <- ref
						}
					}
				}
				c.inner <- digest
				c.advancedCommitPointer()
			} else if ptern[c.commitNode] == toskip {
				logger.Debug.Printf("skip leader round %d node %d \n", c.commitRound, c.commitNode)
				c.advancedCommitPointer()
			} else if ptern[c.commitNode] == undecide {
				break
			} else if ptern[c.commitNode] == unjudge {
				break
			} else if ptern[c.commitNode] == mvbaing {
				break
			}
		}

	}
}

func (c *Commitor) IsReceivePattern(round int, slot core.NodeID) pattern {
	c.mucDAG.RLock()
	defer c.mucDAG.RUnlock()
	item, ok := c.certDAG[round]
	if !ok {
		return unjudge
	}
	ptern, ok := item[slot]
	if !ok {
		return unjudge
	}
	return ptern
}

func (c *Commitor) advancedJudingPointer() {
	c.judingnode++
	if c.judingnode >= core.NodeID(c.parameter.EndProposer+1) {
		c.judingnode = core.NodeID(c.parameter.StartProposer)
		c.judinground++
	}
}

func (c *Commitor) advancedCommitPointer() {
	c.commitNode++
	if c.commitNode >= core.NodeID(c.parameter.EndProposer+1) {
		c.commitNode = core.NodeID(c.parameter.StartProposer)
		c.commitRound++
	}
}

func (c *Commitor) NotifyToJudge() {
	c.notify <- struct{}{}
}

// func (c *Commitor) ifLossLiveness() bool {

//		return true
//	}

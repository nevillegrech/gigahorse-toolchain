pragma solidity ^0.5.0;

contract VickreyAuction {

    struct BidderInfo{
        bytes32 commitment;
        uint256 depositAmount;
    }


    uint256 commitTimeEndBlock;
    uint256 revealTimeEndBlock;
    uint256 minDepositAmount;
    uint256 minPrice;

    mapping(address => BidderInfo) bidders;

    address payable winner;
    uint256 winningBid;
    uint256 runnerUpBid;

    // constructor
    constructor (uint256 reservePrice,
                            uint256 commitTimePeriod, uint256 revealTimePeriod,
                            uint256 bidDepositAmount, bool testMode) public {
        _testMode = testMode;
        _creator = msg.sender;
        minPrice = reservePrice;
        minDepositAmount = bidDepositAmount;
        commitTimeEndBlock = getBlockNumber() + commitTimePeriod - 1;
        revealTimeEndBlock = commitTimeEndBlock + revealTimePeriod;
    }

    // Record the player's bid commitment
    // Make sure at least _bidDepositAmount is provided
    // Only allow commitments before the _bidCommitmentDeadline
    function commitBid(bytes32 bidCommitment) public payable returns(bool) {
        require(getBlockNumber() <= commitTimeEndBlock, "You can only commit during the commitment period.");
        require(msg.value == minDepositAmount, "Commitment deposit lower than the minimum.");
        bidders[msg.sender] = BidderInfo({commitment: bidCommitment, depositAmount: msg.value});

    }

    // Get bidder's commitment
    function getCommitment(address bidder) public view returns (bytes32) {
        return bidders[bidder].commitment;
    }

    // Check that the bid (msg.value) matches the commitment
    // Ignore the bid if it is less than the reserve price
    // Update the highest price, second highest price, highest bidder
    // If the second highest bidder is replaced, send them a refund
    function revealBid(bytes32 nonce) public payable returns(address highestBidder) {
        bool refund;
        uint256 bidAmount = msg.value;
        require(getBlockNumber() > commitTimeEndBlock && getBlockNumber() <= revealTimeEndBlock, "You can only reveal your bid during the reveal period.");
        require(makeCommitment(nonce, bidAmount) == getCommitment(msg.sender), "Commitment not valid.");
        require(bidAmount >= minPrice);
        if(bidAmount > winningBid){
            winner.transfer(winningBid + bidders[winner].depositAmount);
            bidders[winner].depositAmount = 0;
            runnerUpBid = winningBid;
            winningBid = bidAmount;
            winner = msg.sender;
        }
        else if(bidAmount > runnerUpBid){
            runnerUpBid = bidAmount;
            refund = true;
        }
        else{
            refund = true;
        }
        
        if(refund){
            require(bidders[msg.sender].depositAmount != 0, "You can only get refunded once.");
            msg.sender.transfer(bidAmount + bidders[msg.sender].depositAmount);
            bidders[msg.sender].depositAmount = 0;
        }
        return winner;
        
    }

    // Handle the end of the auction
    // Refund the difference between the first price and second price
    function finalize() public creatorOnly {
        require(getBlockNumber() > revealTimeEndBlock, "Auction can be finalized after the reveal phase is over.");
        winner.transfer(winningBid - runnerUpBid + bidders[winner].depositAmount);
        selfdestruct(address(0));
    }

    // Commitment utility
    function makeCommitment(bytes32 nonce, uint256 bidValue) public pure returns(bytes32) {
        return keccak256(abi.encodePacked(nonce, bidValue));
    }

    // Return the current highest bidder
    function getHighestBidder() public view returns (address){
      return winner;
    }

    // Return the current highest bid
    function getHighestBid() public view returns (uint256){
      return winningBid;
    }

    // Return the current second highest bid
    function getSecondHighestBid() public view returns (uint256){
      return runnerUpBid;
    }

    // No need to change any code below here

    bool _testMode;
    uint256 public _testTime;
    address _creator;

    modifier testOnly {
      require(_testMode);
      _;
    }

    modifier creatorOnly {
      require(msg.sender == _creator);
      _;
    }

    function overrideTime(uint256 time) public creatorOnly testOnly {
        _testTime = time;
    }

    function getBlockNumber() public view returns (uint256) {
        if (_testMode) return _testTime;
        return block.number;
    }
}

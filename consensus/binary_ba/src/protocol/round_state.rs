use std::collections::{HashSet, HashMap};

use consensus::LargeField;
use lambdaworks_math::polynomial::Polynomial;
use types::Replica;

pub type Val = i64;

/**
 * Each round of [ABY'22]'s binary BA protocol. 
 * This protocol consists of ECHO1, ECHO2, and ECHO3 messages. 
 * It terminates in 3 round trips in the best case. 
 */
#[derive(Debug,Clone)]
pub struct RoundStateBin{
    // Map of Replica, and binary state of two values, their echos list and echo2 list, list of values for which echo1s were sent and echo2s list
    pub state: Vec<(Val,HashSet<Replica>,HashSet<Replica>,bool,bool)>,
    pub echo1vals: HashSet<Val>,
    pub echo2vals: Vec<Val>,
    pub echo3vals: HashMap<Replica,Val>,
    pub echo3sent: bool,
    pub termval: Option<Val>,
    pub coin_shares_vec: HashMap<Replica,LargeField>,
    pub coin_state: Option<bool>,

    pub num_nodes: usize,
    pub num_faults: usize,

    pub min_threshold: usize,
    pub high_threshold: usize,
}

impl RoundStateBin{
    pub fn new_with_echo(msg: Val,echo_sender:Replica, num_faults: usize ,num_nodes: usize)-> RoundStateBin{
        let mut rnd_state = RoundStateBin{
            state:Vec::new(),
            echo1vals: HashSet::new(),
            echo2vals: Vec::new(),
            echo3vals: HashMap::default(),
            echo3sent:false,
            termval:None,
            coin_shares_vec: HashMap::default(),
            coin_state: None,

            num_nodes: num_nodes,
            num_faults: num_faults,

            min_threshold: num_faults+1,
            high_threshold: num_nodes - num_faults,
        };
        let parsed_bigint = Self::to_target_type(msg.clone());
        //let mut arr_state:Vec<(u64,HashSet<Replica>,HashSet<Replica>,bool,bool)> = Vec::new();
        let mut echo1_set = HashSet::new();
        echo1_set.insert(echo_sender);
        let echo2_set:HashSet<Replica>=HashSet::new();
        rnd_state.state.push((parsed_bigint,echo1_set,echo2_set,false,false));
        rnd_state
    }

    pub fn new_with_echo2(msg: Val,
        echo2_sender:Replica,
        num_faults: usize, 
        num_nodes: usize
    )-> RoundStateBin{
        let mut rnd_state = RoundStateBin{
            state:Vec::new(),
            echo1vals: HashSet::new(),
            echo2vals: Vec::new(),
            echo3vals: HashMap::default(),
            echo3sent:false,
            termval:None,
            coin_shares_vec: HashMap::default(),
            coin_state: None,

            num_nodes: num_nodes,
            num_faults: num_faults,

            min_threshold: num_faults+1,
            high_threshold: num_nodes - num_faults,
        };
        let parsed_bigint = Self::to_target_type(msg.clone());
        let mut echo2_set = HashSet::new();
        echo2_set.insert(echo2_sender);
        let echo1_set:HashSet<Replica>=HashSet::new();
        rnd_state.state.push((parsed_bigint,echo1_set,echo2_set,false,false));
        rnd_state
    }

    pub fn new_with_echo3(msg: Val, 
        echo3_sender:Replica,
        num_faults: usize, 
        num_nodes: usize
    )-> RoundStateBin{
        let parsed_bigint = Self::to_target_type(msg.clone());
        let mut echo3_map:HashMap<Replica, i64> = HashMap::default();
        echo3_map.insert(echo3_sender,msg);
        let echo1_set:HashSet<Replica>=HashSet::new();
        let echo2_set:HashSet<Replica> = HashSet::new();
        let mut rnd_state = RoundStateBin{
            state:Vec::new(),
            echo1vals: HashSet::new(),
            echo2vals: Vec::new(),
            echo3vals: echo3_map,
            echo3sent:false,
            termval:None,
            coin_shares_vec: HashMap::default(),
            coin_state: None,

            num_nodes: num_nodes,
            num_faults: num_faults,

            min_threshold: num_faults+1,
            high_threshold: num_nodes - num_faults,
        };
        rnd_state.state.push((parsed_bigint,echo1_set,echo2_set,false,false));
        rnd_state
    }

    pub fn new_with_pcoin(coin_share: LargeField, share_sender:Replica,
        num_faults: usize, 
        num_nodes: usize)-> RoundStateBin{
        let mut coinmap = HashMap::default();
        coinmap.insert(share_sender, coin_share);
        
        RoundStateBin{
            state:Vec::new(),
            echo1vals: HashSet::new(),
            echo2vals: Vec::new(),
            echo3vals: HashMap::default(),
            echo3sent:false,
            termval:None,
            coin_shares_vec: coinmap,
            coin_state: None,

            num_nodes: num_nodes,
            num_faults: num_faults,

            min_threshold: num_faults+1,
            high_threshold: num_nodes - num_faults,
        }
    }

    pub fn add_echo(&mut self, msg: Val, echo_sender:Replica)-> (Option<Val>,Option<Val>,Option<Val>){
        let mut echo1_msg:Option<Val> = None;
        let mut echo2_msg:Option<Val> = None;
        let mut echo3_msg:Option<Val> = None;
        let parsed_bigint = Self::to_target_type(msg.clone());
        //if self.state.contains_key(&rep){
        //let arr_tup = self.state.get_mut(&rep).unwrap();
        let arr_vec = &mut self.state;
        // The echo sent by echo_sender was for this value in the bivalent initial value state
        if arr_vec[0].0 == parsed_bigint{
            arr_vec[0].1.insert(echo_sender);
            // check for t+1 votes: if it has t+1 votes, send out another echo1 message
            // check whether an echo has been sent out for this value in this instance
            if arr_vec[0].1.len() >= self.min_threshold && !arr_vec[0].3{
                //arr_vec[0].1.insert(myid);
                echo1_msg = Some(msg.clone());
                arr_vec[0].3 = true;
            }
            // check for 2t+1 votes: if it has 2t+1 votes, send out echo2 message
            else if arr_vec[0].1.len() >= self.high_threshold && !arr_vec[0].4{
                self.echo1vals.insert(parsed_bigint);
                // If you send out ECHO2 messages for two values, you should terminate immediately and not wait for 2t+1 ECHO2 messages
                if self.echo1vals.len() == 2{
                    let vec_arr:Vec<Val> = self.echo1vals.clone().into_iter().map(|x| x).collect();
                    let next_round_val = (vec_arr[0].clone()+vec_arr[1].clone())/2;
                    // Send Echo3 from here itself
                    echo3_msg = Some(next_round_val);
                }
                else{
                    echo2_msg = Some(msg.clone());
                }
                arr_vec[0].4 = true;
            }
        }
        else{
            if arr_vec.len() == 1{
                // insert new array vector
                let mut echo_set:HashSet<Replica>= HashSet::default();
                echo_set.insert(echo_sender);
                arr_vec.push((parsed_bigint,echo_set,HashSet::default(),false,false));
            }
            else {
                arr_vec[1].1.insert(echo_sender);
                if arr_vec[1].1.len() >= self.min_threshold && !arr_vec[1].3{
                    //arr_vec[1].1.insert(myid);
                    echo1_msg = Some(msg.clone());
                    arr_vec[1].3 = true;
                }
                else if arr_vec[1].1.len() >= self.high_threshold && !arr_vec[1].4{
                    self.echo1vals.insert(parsed_bigint);
                    if self.echo1vals.len() == 2{
                        // terminate protocol for instance &rep
                        let vec_arr:Vec<Val> = self.echo1vals.clone().into_iter().map(|x| x).collect();
                        let next_round_val = (vec_arr[0].clone()+vec_arr[1].clone())/2;
                        // Send echo3 from here
                        echo3_msg = Some(next_round_val);
                    }
                    else {
                        echo2_msg = Some(msg.clone());
                    }
                    arr_vec[1].4 = true;
                }
            }
        }
        (echo1_msg,echo2_msg,echo3_msg)
    }

    pub fn add_echo2(&mut self,msg: Val, echo2_sender:Replica)->Option<Val>{
        let mut echo3_msg:Option<Val> = None;
        let parsed_bigint = Self::to_target_type(msg.clone());
        // this vector can only contain two elements, if the echo corresponds to the first element, the first if block is executed
        let arr_vec = &mut self.state;
        if arr_vec[0].0 == parsed_bigint{
            arr_vec[0].2.insert(echo2_sender);
            // check for 2t+1 votes: if it has 2t+1 votes, then terminate
            if arr_vec[0].2.len() >= self.high_threshold{
                self.echo2vals.push(parsed_bigint);
                // send echo3 from here
                if !self.echo3sent{
                    echo3_msg = Some(parsed_bigint);
                    self.echo3sent = true;
                }
            }
        }
        else{
            if arr_vec.len() == 1{
                // insert new array vector
                let mut echo2_set:HashSet<Replica>= HashSet::default();
                echo2_set.insert(echo2_sender);
                arr_vec.push((parsed_bigint,HashSet::default(),echo2_set,false,false));
            }
            else{
                arr_vec[1].2.insert(echo2_sender);
                if arr_vec[1].2.len() >= self.high_threshold{
                    self.echo2vals.push(parsed_bigint);
                    // Send echo3 from here
                    if !self.echo3sent{
                        echo3_msg = Some(parsed_bigint);
                        self.echo3sent = true;
                    }
                }
            }
        }
        echo3_msg
    }

    pub fn add_echo3(&mut self,msg: Val, echo3_sender:Replica)->bool{
        if !self.echo3vals.contains_key(&echo3_sender){
            self.echo3vals.insert(echo3_sender, msg);
            if self.echo3vals.len() >= self.high_threshold && self.termval.is_none(){
                if self.echo1vals.len() == 1{
                    // terminate with the value provided
                    let info_vec = Vec::from_iter(self.echo1vals.clone());
                    self.termval = Some(*info_vec.first().unwrap());
                    return true;
                }
                else {
                    let info_vec = Vec::from_iter(self.echo1vals.clone());
                    self.termval = Some((info_vec.first().unwrap()+info_vec.last().unwrap())/2);
                    return true;
                }
            }
            else {
                return false;
            }
        }
        match self.termval {
            Some(_x)=> true,
            None => false
        }
    }
    pub fn to_target_type(msg:Val)->Val{
        msg
        // let mut msg_bytes = [0u8;8];
        // msg_bytes.clone_from_slice(msg.as_slice());
        // u64::from_be_bytes(msg_bytes)
    }

    // Aggregates partial coinnatures and returns an option indicating whether the protocol is moving to the next round
    // Or whether it can terminate in this round
    pub fn aggregate_p_coins(&mut self)->Option<(bool,Val)>{
        if self.coin_shares_vec.len() < self.min_threshold{
            return None;
        }
        // Interpolate coin
        let mut evaluation_points = Vec::new();
        let mut shares = Vec::new();

        for rep in 0..self.num_nodes{
            if self.coin_shares_vec.contains_key(&rep){
                evaluation_points.push(LargeField::from(rep as u64));
                shares.push(self.coin_shares_vec.get(&rep).unwrap().clone());
            }
        }

        // TODO: Replace with online error correction
        let coin = Polynomial::interpolate(&evaluation_points, &shares).unwrap().evaluate(&LargeField::from(0 as u64));
        let result = (coin.to_bytes_be()[0]%2) == 0;

        log::info!("Coin value {} from reconstructed coin {:?} and round termination value {:?}",result, coin,self.termval);
        if self.termval.is_some(){
            if (self.termval.unwrap() == 2 && result) || (self.termval.unwrap() == 0 && !result){
                // Terminate and send message to syncer
                return Some((true,self.termval.unwrap()));
            }
            else {
                if self.echo1vals.len() == 2{
                    // If you get two values with 2f+1 ECHOs, take up the value of the coin
                    if result{
                        return Some((false,2));
                    }
                    else {
                        return Some((false,0));
                    }
                }
                else {
                    let values = self.echo1vals.clone();
                    let val = Vec::from_iter(values.into_iter()).get(0).unwrap().clone();
                    return Some((false,val));
                }
            }
        }
        else {
            return None;   
        }
    }

    pub fn add_partial_coin(&mut self,id:Replica,partial_coin: LargeField){
        self.coin_shares_vec.insert(id, partial_coin);
    }

    pub fn contains_coin(&self,id: Replica)->bool{
        self.coin_shares_vec.contains_key(&id)
    }
}
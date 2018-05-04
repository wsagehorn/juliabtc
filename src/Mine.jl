module Mine

using SHA
using JSON


#=========================#
#=     Cryptography      =#
#=========================#

function dSHA2(in::String)
    return dSHA2(hex2bytes(in))
end

function dSHA2(in::Array{UInt8})
    return bytes2hex(sha256(sha256(in)))
end

# convert big endian to little endian, no builtins!
function be2le(s)
    le = ""
    for i = 0: Int(floor(length(s)/8) - 1)
        #print(s[i*8+1:(i+1)*8], "\n")
        le *= num2hex(bswap(hex2num(s[i*8+1:(i+1)*8])))
    end
    return le
end

#=========================#
#= Coinbase  Transaction =#
#=========================#

mutable struct CoinbaseTransaction
    coinb1::String
    extranonce1::String
    extranonce2_size::Int32
    coinb2::String
    extranonce2::UInt32
    CoinbaseTransaction(coinb1, extranonce1, extranonce2_size, coinb2) =
        new(coinb1, extranonce1, extranonce2_size, coinb2, UInt32(0))
end

# increments without changing type (addition casts to Int64)
# overflow is impossible for extranonce2
function incrementNonce!(cbt::CoinbaseTransaction)
    cbt.extranonce2 = typeof(cbt.extranonce2)(cbt.extranonce2 + 1)
end

# hashes CoinbaseTransaction for use in calculating Merkle root
function hash(cbt::CoinbaseTransaction)
    s = cbt.coinb1 *
        cbt.extranonce1 *
        hex(cbt.extranonce2, cbt.extranonce2_size * 2) *
        cbt.coinb2
    return dSHA2(s)
end



#=========================#
#=      Merkle root      =#
#=========================#

function buildMerkelRoot(coinbaseHash::String, merkleBranches::Array{String})
    root = coinbaseHash
    for branch in merkleBranches
        root = dSHA2(root * branch)
    end
    return root
end



#=========================#
#=     Block Header      =#
#=========================#

mutable struct BlockHeader
    version::String
    prevhash::String
    merkle_root::String
    timestamp::String
    bits::String
    nonce::UInt32
    BlockHeader(version, prevhash, merkle_root, timestamp, bits) =
        new(version, prevhash, merkle_root, timestamp, bits, UInt32(0))
end

# increments the nonce (preserves type)
# returns true if overflow occured, false otherwise
function incrementNonce!(bh::BlockHeader)
    bh.nonce = typeof(bh.nonce)(bh.nonce + 1)
    return bh.nonce == 0
end

function incrementNonce_r!(bh::BlockHeader)
    bh.nonce = typeof(bh.nonce)(bh.nonce + 1)
    return bh
end

# hashes header for evaluation against difficulty
function hash(bh::BlockHeader)
    s = be2le(bh.version) *
        be2le(bh.prevhash) *
        bh.merkle_root *
        bh.timestamp *
        bh.bits *
        hex(bh.nonce, 8) *                           # pad to 512
        "000000800000000000000000000000000000000000000000000000000000000000000000000000000000000080020000"
    return dSHA2(s)

end




#=========================#
#=         Job           =#
#=========================#

# A Job contains all the data needed to mine a block,
# directly from the pool.
struct Job
    extranonce1::String
    extranonce2_size::Int32
    difficulty::Int32
    job_id::String
    prevhash::String
    coinb1::String
    coinb2::String
    merkle_branch::Array{String}
    version::String
    nbits::String
    ntime::String
    clean_jobs::Bool
end




#=========================#
#=    Pool Connection    =#
#=========================#

# subscibes to the pool, returns the first job
function subscribe(ip::IPv4, port::Int32)
    conn = connect(ip, port)
    write(conn, """{"id": 1, "method": "mining.subscribe", "params": []}\n""")
    rsp1 = JSON.parse(readline(conn))
    rsp2 = JSON.parse(readline(conn))
    rsp3 = JSON.parse(readline(conn))
    close(conn)

    return Job(
        rsp1["result"][2],  # extranonce1
        rsp1["result"][3],  # extranonce2_size

        rsp2["params"][1],  # difficulty

        rsp3["params"][1],  # job_id
        rsp3["params"][2],  # prevhash
        rsp3["params"][3],  # coinb1
        rsp3["params"][4],  # coinb2
        rsp3["params"][5],  # merkle_branch
        rsp3["params"][6],  # version
        rsp3["params"][7],  # nbits
        rsp3["params"][8],  # ntime
        rsp3["params"][9])  # clean
end

function authorize(ip::IPv4, port::Int32, worker::String, password::String)
    conn = connect(ip, port)
    write(conn, """{"params": ["$(worker)", "$(password)"], "id": 2, "method": "mining.authorize"}\n""")
    rsp1 = JSON.parse(readline(conn))
    #if rsp1["error"] != nothing
        #error("Failed to authorize worker $(worker)\n")
    #else
        #printing is not thread safe :(
        #print("Authorized worker $(worker)\n")
    #end
    close(conn)
end




#=========================#
#=         I / O         =#
#=========================#

struct Config
    poolIP::IPv4
    poolPort::Int32
    worker::String
    password::String
    method::String
end

function loadConfig(path::String)
    c = JSON.parsefile(path)
    return Config(
        IPv4(c["poolIP"]),
        c["poolPort"],
        c["workername"],
        c["password"],
        c["method"])
end

function loadConfig()
    loadConfig("../config.json")
end


function mine_sequential(iterations)

    # load configuration
    config = loadConfig()

    # get job from pool, auth worker
    job = subscribe(config.poolIP, config.poolPort)
    authorize(config.poolIP, config.poolPort, config.worker, config.password)

    # Build coinbase transaction
    coinbase = CoinbaseTransaction(job.coinb1, job.extranonce1,
        job.extranonce2_size, job.coinb2)

    # Calculate Merkle root
    merkleRoot = buildMerkelRoot(hash(coinbase), job.merkle_branch)

    # construct block header
    blockHeader = BlockHeader(job.version, job.prevhash, merkleRoot,
        job.ntime, job.nbits)

    validCount = 0


    tic()
    for i = 0:iterations
        h = hash(blockHeader)
        if h < "0000ffff"#"00000000ffff"
            validCount += 1
        end
        if incrementNonce!(blockHeader)
            # increment extranonce2 and rebuild block
            incrementNonce(coinbase)
            merkleRoot = buildMerkelRoot(hash(coinbase), job.merkle_branch)
            blockHeader = BlockHeader(job.version, job.prevhash, merkleRoot,
                job.ntime, job.nbits)
        end

    end
    elapsedTime = toq()


    return elapsedTime
end


function mine_fine(iterations)

    # load configuration
    config = loadConfig()

    # get job from pool, auth worker
    job = subscribe(config.poolIP, config.poolPort)
    authorize(config.poolIP, config.poolPort, config.worker, config.password)

    # Build coinbase transaction
    coinbase = CoinbaseTransaction(job.coinb1, job.extranonce1,
        job.extranonce2_size, job.coinb2)

    # Calculate Merkle root
    merkleRoot = buildMerkelRoot(hash(coinbase), job.merkle_branch)

    # construct block header
    blockHeader = BlockHeader(job.version, job.prevhash, merkleRoot,
        job.ntime, job.nbits)

    # make our valid count thread-safe
    validCount = Threads.Atomic{Int}(0)

    tic()
    Threads.@threads for i = 0:iterations
        if check_nonce(i, blockHeader::BlockHeader)
            Threads.atomic_add!(validCount, 1)
        end
    end
    elapsedTime = toq()

    return elapsedTime
end

function check_nonce(nonce, blockHeader::BlockHeader)
    blockHeader.nonce = nonce
    h = hash(blockHeader)
    if h < "0000ffff"
        return true
    end
    return false
end

function mine_coarse(iterations)
    # load configuration
    config = loadConfig()

    jobs = Array{Job}(Threads.nthreads())
    elapsedTime = Array{Float64}(Threads.nthreads())

    for i = 1:Threads.nthreads()
        jobs[i] = subscribe(config.poolIP, config.poolPort)
        #elapsedTime[Threads.threadid()] = i
    end

    # divide iterations among worker threads, each with their own job
    Threads.@threads for i = 1:Threads.nthreads()
        elapsedTime[Threads.threadid()] = mine_job(jobs[Threads.threadid()],
            iterations/Threads.nthreads())
    end
    return maximum(elapsedTime)
end


function mine_job(job::Job, iterations)
    #authorize(poolIP, poolPort, worker, password)
    # parallel authorizes blows up and segfaults

    # Build coinbase transaction
    coinbase = CoinbaseTransaction(job.coinb1, job.extranonce1,
        job.extranonce2_size, job.coinb2)

    # Calculate Merkle root
    merkleRoot = buildMerkelRoot(hash(coinbase), job.merkle_branch)

    # construct block header
    blockHeader = BlockHeader(job.version, job.prevhash, merkleRoot,
        job.ntime, job.nbits)

    tic()
    for i = 0:iterations
        h = hash(blockHeader)
        #if h < "0000ffff" #"00000000ffff"
            #validCount += 1
        #end
        if incrementNonce!(blockHeader)
            # increment extranonce2 and rebuild block
            incrementNonce(coinbase)
            merkleRoot = buildMerkelRoot(hash(coinbase), job.merkle_branch)
            blockHeader = BlockHeader(job.version, job.prevhash, merkleRoot,
                job.ntime, job.nbits)
        end
    end
    return toq()

end


function main()

    iterations = 100000

    print("Warming up...\n")
    mine_sequential(1000)
    mine_fine(1000)
    mine_coarse(1000)
    print("Warmed up.\n")

    print("Currently using $(Threads.nthreads()) thread(s)\n")

    print("Checking $(iterations) hashes sequentially...\n")
    elapsedTime = mine_sequential(iterations)
    print("Took $(elapsedTime)s, avg $(iterations/elapsedTime/1000)Kh/s\n\n")

    print("Checking $(iterations) hashes using fine grained parallelism...\n")
    elapsedTime = mine_fine(iterations)
    print("Took $(elapsedTime)s, avg $(iterations/elapsedTime/1000)Kh/s\n\n")

    print("Checking $(iterations) hashes using coarse grained parallelism...\n")
    elapsedTime = mine_coarse(iterations)
    print("Took $(elapsedTime)s, avg $(iterations/elapsedTime/1000)Kh/s\n\n")
end
main()

end

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



#=========================#
#=    Coinbase Block     =#
#=========================#

mutable struct CoinbaseBlock
    coinb1::String
    extranonce1::String
    extranonce2_size::Int32
    coinb2::String
    extranonce2
    CoinbaseBlock(coinb1, extranonce1, extranonce2_size, coinb2) =
        new(coinb1, extranonce1, extranonce2_size, coinb2, UInt32(0))
end

# increments without changing type (addition casts to Int64)
# overflow is impossible for extranonce2
function incrementNonce!(cb::CoinbaseBlock)
    cb.extranonce2 = typeof(cb.extranonce2)(cb.extranonce2 + 1)
end

# hashes CoinbaseBlock for use in calculating Merkle root
function hash(cb::CoinbaseBlock)
    s = cb.coinb1 *
        cb.extranonce1 *
        hex(cb.extranonce2, cb.extranonce2_size * 2) *
        cb.coinb2
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
end

# increments the nonce (preserves type)
# returns true if overflow occured, false otherwise
function incrementNonce!(bh::BlockHeader)
    bh.nonce = typeof(bh.extranonce2)(bh.extranonce2 + 1)
    return bh.nonce == 0
end

# hashes header for evaluation against difficulty
function hash(bh::BlockHeader)
    s = bh.version *
        bh.prevhash *
        bh.merkle_root *
        bh.timestamp *
        bh.bits *
        hex(bh.nonce, 8)
    return dSHA2(s)
end

#=========================#
#=         Job           =#
#=========================#

# A Job contains all the data needed to mine a block,
# directly from the pool.
struct Job
    extranonce1::String
    extranonce2_size::String
    difficulty::String
    job_id::String
    prevhash::String
    coinb1::String
    coinb2::String
    merkle_branch::Array{String}
    version::String
    nbits::String
    ntime::String
    clean_jobs::String
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

function authorize(worker, password)
    conn = connect(ip, port)
    write(conn, """{"params": ["$(worker)", "$(password)"], "id": 2, "method": "mining.authorize"}\n""")
    rsp1 = JSON.parse(readline(conn))
    if rsp1["error"] != nothing
        error("Failed to authorize worker $(worker)")
    else
        print("Authorized worker $(worker)")
    end
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
        c["poolIP"],
        c["poolPort"],
        c["workername"],
        c["password"],
        c["method"])
end

function loadConfig()
    loadConfig("/config.json")
end


conn = connect(ip"52.19.206.69", 3333)


write(conn, """{"id": 1, "method": "mining.subscribe", "params": []}\n""")
rsp1 = JSON.parse(readline(conn))

extranonce1 = rsp1["result"][2]
extranonce2_size = rsp1["result"][3]
JSON.print(rsp1)
print("\n\n")


rsp2 = JSON.parse(readline(conn))
JSON.print(rsp2)
print("\n\n")


difficulty = rsp2["params"][1]

rsp3 = JSON.parse(readline(conn))
JSON.print(rsp3)
print("\n\n")

job_id = rsp3["params"][1]
prevhash = rsp3["params"][2]
coinb1 = rsp3["params"][3]
coinb2 = rsp3["params"][4]
merkle_branch = rsp3["params"][5]
version = rsp3["params"][6]
nbits = rsp3["params"][7]
ntime = rsp3["params"][8]
clean = rsp3["params"][9]

close(conn)


#a = 5
#b = 6
#c = ccall((:add,"clib/testing"),Int32,(Int32,Int32), a, b)

#print(c)



#"""{"id": 1, "method": "mining.subscribe", "params": []}\n""".encode()
"2165060064a4e1"

["465b4",
"170bcd35afb876afb78b0fcbd8dbd7bb81145ed0001dfbfd0000000000000000",
extranonce1 = "2165060064a4e1"
coinb1 = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff450358f107fabe6d6d83822c34eb44c1321d39269d1e6efad4ef2fb54dc8822a5fd872ce87bfbdb0070100000000000000"
coinb2 = "b465042f736c7573682f00000000038fa6954a000000001976a9147c154ed1dc59609e3d26abb2df2ea3d587cd8c4188ac00000000000000002c6a4c2952534b424c4f434b3aa23547f00d8694cf28ebcb0f1d3796b8b9fa13a4f5dc3be9617e1466ed85a5010000000000000000266a24aa21a9ed0f8cc1e340aa2efc3f40737a191ffab91f2ac747d4550433fa3cb03f05b095c400000000"
["f05b352c51ed440d902125d0d21fe21ab623d8868f624fc07a56b9a919e725ee","ee8de35e8a0b56c537f5bcbcb319eb44991b5e21383a37877b4bf38f76899171","9340ba09bcdff536551963f08bdb94a4e1a1f39865f76ad3846a280eefd66494","3cc071b9450a37a6bab0e3b6c3d12a9fa1923392ff1d092fedc7e0f75d1f2fa8","3cad0dd64274d34febb78fd6bb719778576fd1a9d9025357f8f2d10ceb21fa3b","ce0b4681f0e9da7ce405f7ac24e22f7b405f405a9b379476516125803c37a856"]

end

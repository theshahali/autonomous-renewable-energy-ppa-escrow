import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

let createClient, createAccount;
try {
    const gl = await import('genlayer-js');
    createClient = gl.createClient;
    createAccount = gl.createAccount;
} catch (e) {
    const gl = await import('../../AetherDungeon/frontend/node_modules/genlayer-js/dist/index.js');
    createClient = gl.createClient;
    createAccount = gl.createAccount;
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));

async function main() {
    console.log("================================================================================");
    console.log("  AUTONOMOUS RENEWABLE ENERGY PPA ESCROW — STUDIO DEPLOYMENT");
    console.log("================================================================================");
    
    console.log("Connecting to GenLayer Studio RPC: https://studio.genlayer.com/api");
    const account = createAccount();
    console.log("Generated Deployer / Sovereign Operator Address:", account.address);

    const client = createClient({
        endpoint: 'https://studio.genlayer.com/api',
        account: account
    });

    const contractPath = path.join(__dirname, '..', 'contracts', 'AutonomousRenewableEnergyPpaEscrow.py');
    const code = fs.readFileSync(contractPath, 'utf8');
    console.log(`Read contract code from contracts/AutonomousRenewableEnergyPpaEscrow.py (${code.length} bytes)`);

    const owner = account.address;

    console.log("Broadcasting deployContract transaction to GenLayer Studio...");
    try {
        const txHash = await client.deployContract({
            code: code,
            args: [owner]
        });
        console.log("Deployment transaction submitted! Tx Hash:", txHash);

        console.log("Waiting for transaction receipt on GenLayer (status: FINALIZED)...");
        const receipt = await client.waitForTransactionReceipt({
            hash: txHash,
            status: 'FINALIZED',
            interval: 3000,
            retries: 50
        });

        console.log("Receipt status:", receipt.status);
        const contractAddress = receipt.to || receipt.contractAddress || receipt.data?.contractAddress || receipt.recipient;
        console.log("Contract Address:", contractAddress);

        if (contractAddress) {
            console.log("\n>>> DEPLOYMENT SUCCESSFUL! <<<");
            console.log("Contract Address:", contractAddress);
            console.log("Explorer URL: https://explorer-studio.genlayer.com/address/" + contractAddress);

            // Verify live on-chain reads with retry loop for state indexing
            console.log("\n--- VERIFYING LIVE ON-CHAIN RENEWABLE PPA ESCROW STATE ---");
            let escrowCount = 0;
            let totalVolume = "0";
            let deployerClaimable = "0";
            for (let i = 0; i < 15; i++) {
                try {
                    escrowCount = await client.readContract({
                        address: contractAddress,
                        functionName: 'get_total_escrows',
                        args: []
                    });
                    totalVolume = await client.readContract({
                        address: contractAddress,
                        functionName: 'get_total_volume_locked',
                        args: []
                    });
                    deployerClaimable = await client.readContract({
                        address: contractAddress,
                        functionName: 'get_claimable_balance',
                        args: [account.address]
                    });
                    console.log("State indexer synchronized!");
                    break;
                } catch (readErr) {
                    console.log(`Waiting for state indexer (attempt ${i + 1}/15)...`);
                    await new Promise(r => setTimeout(r, 3000));
                }
            }
            console.log("Total PPA Escrows Created:", escrowCount);
            console.log("Total Volume Locked (Wei):", totalVolume);
            console.log("Deployer Claimable Balance (Wei):", deployerClaimable);

            const manifest = {
                contractName: "AutonomousRenewableEnergyPpaEscrow",
                contractAddress: contractAddress,
                transactionHash: txHash,
                deployerAddress: account.address,
                network: "GenLayer Studio Testnet",
                rpcEndpoint: "https://studio.genlayer.com/api",
                explorerUrl: "https://explorer-studio.genlayer.com/address/" + contractAddress,
                deployedAt: new Date().toISOString(),
                initialState: {
                    totalEscrowsCreated: Number(escrowCount),
                    totalVolumeLockedWei: String(totalVolume),
                    deployerClaimableBalanceWei: String(deployerClaimable)
                }
            };

            const manifestPath = path.join(__dirname, '..', 'deployment_manifest.json');
            fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2), 'utf8');
            console.log(`Saved deployment manifest to: ${manifestPath}`);
        } else {
            console.error("No contract address returned in transaction receipt!");
        }

    } catch (err) {
        console.error("Deployment failed:", err);
        process.exit(1);
    }
}

main();

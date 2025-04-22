import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { DeeperSolana } from "../target/types/deeper_solana";
import { PublicKey, Keypair, Ed25519Program, SYSVAR_INSTRUCTIONS_PUBKEY } from '@solana/web3.js';
import assert from 'node:assert';
import nacl from "tweetnacl";


describe("deeper-solana", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const program = anchor.workspace.deeperSolana as Program<DeeperSolana>;

  const payer = provider.wallet as anchor.Wallet;
  const [configPDA] = PublicKey.findProgramAddressSync([Buffer.from('config')], program.programId);

  const user1 = Keypair.generate();
  const user2 = Keypair.generate();
  const nonAdmin = Keypair.generate();

  // Derive credit PDAs for users
  const [creditPDA1, creditBump1] = PublicKey.findProgramAddressSync(
    [Buffer.from("credit"), user1.publicKey.toBuffer()],
    program.programId
  );
  const [creditPDA2, creditBump2] = PublicKey.findProgramAddressSync(
    [Buffer.from("credit"), user2.publicKey.toBuffer()],
    program.programId
  );

  it("Creates credit account for user1 via setCredit", async () => {
    const tx = await program.methods
      .initialize(payer.publicKey)
      .accounts({ dpr_config: configPDA, payer: payer.publicKey }).rpc();

    console.log("Your transaction signature", tx);
    const userAccount = await program.account.config.fetch(configPDA);
    assert.equal(userAccount.admin.toBase58(), payer.publicKey.toBase58());

    await program.methods
      .setCredit(new anchor.BN(100))
      .accounts({
        payer: payer.publicKey,
        dpr_config: configPDA,
        user: user1.publicKey,
        credit_info: creditPDA1,
        system_program: anchor.web3.SystemProgram.programId,
      })
      .rpc();

    const creditAccount = await program.account.creditInfo.fetch(creditPDA1);
    assert.equal(creditAccount.user.toBase58(), user1.publicKey.toBase58());
    assert.equal(creditAccount.number.toString(), "100");
  });

  it("Updates user1's credit account via setCredit", async () => {
    await program.methods
      .setCredit(new anchor.BN(200))
      .accounts({
        payer: payer.publicKey,
        dpr_config: configPDA,
        user: user1.publicKey,
        credit_info: creditPDA1,
        system_program: anchor.web3.SystemProgram.programId,
      })
      .rpc();

    const creditAccount = await program.account.creditInfo.fetch(creditPDA1);
    assert.equal(creditAccount.user.toBase58(), user1.publicKey.toBase58());
    assert.equal(creditAccount.number.toString(), "200");
  });

  it("Creates and sets credit account for user2 via setCredit", async () => {
    await program.methods
      .setCredit(new anchor.BN(300))
      .accounts({
        payer: payer.publicKey,
        dpr_config: configPDA,
        user: user2.publicKey,
        credit_info: creditPDA2,
        system_program: anchor.web3.SystemProgram.programId,
      })
      .rpc();

    const creditAccount = await program.account.creditInfo.fetch(creditPDA2);
    assert.equal(creditAccount.user.toBase58(), user2.publicKey.toBase58());
    assert.equal(creditAccount.number.toString(), "300");
  });

  it("Fails to set credit as non-admin", async () => {
    await provider.connection.requestAirdrop(nonAdmin.publicKey, 1e9);
    await new Promise((resolve) => setTimeout(resolve, 1000));

    let error = null;
    try {
      await program.methods
        .setCredit(new anchor.BN(400))
        .accounts({
          payer: nonAdmin.publicKey,
          dpr_config: configPDA,
          user: user1.publicKey,
          credit: creditPDA1,
          system_program: anchor.web3.SystemProgram.programId,
        })
        .signers([nonAdmin])
        .rpc();
    } catch (err) {
      error = err;
    }

    assert(error, "Expected an error");
    assert(error.message.includes("Only the admin can perform this action"));

    const creditAccount = await program.account.creditInfo.fetch(creditPDA1);
    assert.equal(creditAccount.number.toString(), "200"); // Still 200
  });
});

describe("ed25519_verify_sysvar", () => { // Updated describe block
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  // Adjust the program type cast
  const program = anchor.workspace.deeperSolana as Program<DeeperSolana>;
  const wallet = provider.wallet as anchor.Wallet;

  // Ed25519 keypair for signing messages
  const messageSigner = nacl.sign.keyPair();
  const messageSignerPublicKey = Buffer.from(messageSigner.publicKey);
  const messageSignerSecretKey = Buffer.from(messageSigner.secretKey);

  it("Successfully verifies a valid Ed25519 signature via Sysvar", async () => { // Updated test description
    const message = Buffer.from("Sysvar verification test message", "utf-8");
    const signature = Buffer.from(nacl.sign.detached(message, messageSignerSecretKey));

    console.log("Message:", message.toString());
    console.log("Public Key (Buffer):", messageSignerPublicKey);
    console.log("Signature (Buffer):", signature);
    console.log("Signer (Wallet):", wallet.publicKey.toBase58());

    // *** Create the Ed25519 Program instruction ***
    const ed25519Instruction = Ed25519Program.createInstructionWithPublicKey({
      publicKey: messageSignerPublicKey,
      message: message,
      signature: signature,
      // Optional: instructionIndex can usually be omitted or set to default
      // when creating the instruction like this for preInstructions.
      // The runtime handles indexing relative to the transaction.
    });

    console.log(ed25519Instruction.data.toString('hex'));
    console.log("message lenght", message.length);

    try {
      const tx = await program.methods
        .verifyEd25519ViaSysvar( // Call the correct method name
          messageSignerPublicKey,
          message,
          signature
        )
        .accounts({
          signer: wallet.publicKey,
          instructionSysvar: SYSVAR_INSTRUCTIONS_PUBKEY, // Pass the sysvar account ID
        })
        .preInstructions([ed25519Instruction]) // *** Add Ed25519 ix *before* ours ***
        .rpc({ commitment: "confirmed" });

      console.log("Your transaction signature", tx);

      const txInfo = await provider.connection.getTransaction(tx, { commitment: "confirmed", maxSupportedTransactionVersion: 0 });
      console.log("Transaction Logs:\n", txInfo?.meta?.logMessages?.join("\n"));

      // expect(txInfo?.meta?.logMessages).to.include("Verification successful: Preceding Ed25519 instruction data matches arguments.");
      // expect(txInfo?.meta?.err).to.be.null;

    } catch (error) {
      console.error("Error sending transaction:", error);
      if (error instanceof anchor.AnchorError) {
        console.error("Anchor Error:", error.error);
        console.error("Error Logs:", error.logs);
      } else if (error.logs) {
        console.error("Transaction Logs:", error.logs);
      }
      throw error;
    }
  });
});

describe("credit_setting", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const program = anchor.workspace.deeperSolana as Program<DeeperSolana>;

  const payer = provider.wallet as anchor.Wallet;
  it("credit_setting", async () => {
    const idx0 = 0;
    const idxBuffer = Buffer.alloc(2);
    idxBuffer.writeUInt16LE(0);

    const [settingsAccountPda0] = PublicKey.findProgramAddressSync(
      [Buffer.from("settings"), idxBuffer],
      program.programId);

    const newSettings = [
      { apyNumerator : 100, stakingBalance : new anchor.BN(200) },
      { apyNumerator : 200, stakingBalance :new anchor.BN(200) },
    ];

    try {
    const tx = await program.methods
      .setSettings(idx0, newSettings)
      .accounts({
        settings_account: settingsAccountPda0,
        signer:  payer.publicKey,
        system_program: anchor.web3.SystemProgram.programId,
      })
      .rpc({ commitment: "confirmed" });
    console.log("Set settings for account idx 0:", settingsAccountPda0.toBase58());
    const txInfo = await provider.connection.getTransaction(tx, {
      maxSupportedTransactionVersion: 0,
      commitment: "confirmed",
    });

   //console.log("Transaction Logs:\n", txInfo?.meta?.logMessages?.join("\n"));

   const tx2 = await program.methods
      .addSetting(idx0, 500, anchor.BN(500))
      .accounts({
        settings_account: settingsAccountPda0,
        signer: payer.publicKey,
        system_program: anchor.web3.SystemProgram.programId,
      })
      .rpc({ commitment: "confirmed" });


    const settingsAccount = await program.account.creditSettingsAccount.fetch(settingsAccountPda0);
    console.log("settingsAccount :", settingsAccount);
    const result = await program.methods
      .getSetting(idx0, 2)
      .accounts({
        settings_account: settingsAccountPda0,
      })
      .view();
      
    console.log("Setting at index 0 in account idx 0:", result);

  } catch (error) {
    console.error("Error sending transaction:", error);
    if (error instanceof anchor.AnchorError) {
      console.error("Anchor Error:", error.error);
      console.error("Error Logs:", error.logs);
    } else if (error.logs) {
      console.error("Transaction Logs:", error.logs);
    }
    throw error;
  }

  });
});

// it("Fails verification via Sysvar with a tampered signature", async () => {
//   const message = Buffer.from("Another message for sysvar", "utf-8");
//   const correctSignature = Buffer.from(nacl.sign.detached(message, messageSignerSecretKey));

//   const tamperedSignature = Buffer.from(correctSignature);
//   tamperedSignature[0] = tamperedSignature[0] ^ 0xff; // Tamper it

//   // *** The Ed25519 instruction itself will contain the TAMPERED signature ***
//   const ed25519Instruction = Ed25519Program.createInstructionWithPublicKey({
//       publicKey: messageSignerPublicKey,
//       message: message,
//       signature: tamperedSignature, // Use tampered signature here
//   });

//   try {
//     await program.methods
//       .verifyEd25519ViaSysvar(
//         Array.from(messageSignerPublicKey),
//         message,
//         Array.from(tamperedSignature) // Pass tampered sig to our program too (for comparison)
//       )
//       .accounts({
//         signer: wallet.publicKey,
//         instructionSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
//       })
//       .preInstructions([ed25519Instruction]) // Include the Ed25519 instruction that WILL FAIL
//       .rpc();

//     assert.fail("Transaction should have failed at the runtime level due to invalid Ed25519 signature");
//   } catch (error) {
//     // IMPORTANT: Because the Ed25519 precompile instruction itself fails validation
//     // by the Solana runtime, the *entire transaction* will fail before our
//     // program's logic for checking the sysvar even gets definitively executed or committed.
//     // The error might not be a specific AnchorError from *our* program's require! checks,
//     // but rather a more general transaction simulation/processing error.
//     console.log("Caught expected error (transaction simulation failed):", error.message);
//     //expect(error.message).to.match(/Transaction simulation failed|custom program error|Signature verification failed/i);

//     // You might still see logs from your program attempting to run *during simulation*
//     if (error.logs) {
//         console.log("Logs during failed simulation:\n", error.logs.join("\n"));
//         // We expect a log indicating the Ed25519 program itself failed.
//         //expect(error.logs.some(log => /Program Ed25519Program.* failed|signature verification failed/i.test(log))).to.be.true;
//     }
//   }
// });

// Add other failure case tests from the original Sysvar example (missing pre-ix, wrong pre-ix, data mismatch)
// These tests WILL fail within *your* Anchor program's checks (require! statements)
// and should throw the specific AnchorErrors (NoPrecedingInstruction, InvalidPrecedingInstructionProgram, etc.)
// ... (include those tests here, adapted for the new function/program names) ...

//});
import * as anchor from "@coral-xyz/anchor";
import { Program, BorshCoder } from "@coral-xyz/anchor";
import { DeeperSolana } from "../target/types/deeper_solana";
import { PublicKey, Keypair, Ed25519Program, SYSVAR_INSTRUCTIONS_PUBKEY } from '@solana/web3.js';
import assert from 'node:assert';
import nacl from "tweetnacl";
// import * as borsh from "@coral-xyz/borsh";

const devKey = Keypair.generate();

interface DayCredit {
  campaign: number;
  day: number;
  credit: number;
}

interface DayCreditHistory {
  history: DayCredit[];
}

function curDay(): number {
  console.log("Current timestamp:", Date.now());
    const currentSecond: number = (Date.now() - 1735689600000) / 1000;
    return (currentSecond / 86400) as number; // 86400 seconds in a day
}


describe("deeper-solana", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.deeperSolana as Program<DeeperSolana>;
  const payer = provider.wallet as anchor.Wallet;
  const [configPDA] = PublicKey.findProgramAddressSync([Buffer.from('config')], program.programId);

  const oldDevKey = Keypair.generate();
  const oldAdmin = Keypair.generate();
  console.log("Old Admin Keypair:", oldAdmin.publicKey.toBase58());
  console.log("Old Dev Keypair:", oldDevKey.publicKey.toBase58());
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

  it("Updates admin and dev key", async () => {
    await provider.connection.requestAirdrop(oldAdmin.publicKey, 10e9);
    await new Promise((resolve) => setTimeout(resolve, 1000));

    const tx = await program.methods
      .initialize(oldAdmin.publicKey, oldDevKey.publicKey)
      .accounts({
        dpr_config: configPDA,
        payer: oldAdmin.publicKey,
        system_program: anchor.web3.SystemProgram.programId
      }).signers([oldAdmin]).rpc();

    console.log("Your transaction signature", tx);
    const configAccount = await program.account.config.fetch(configPDA);
    assert.equal(configAccount.admin.toBase58(), oldAdmin.publicKey.toBase58());
    assert.equal(configAccount.devKey.toBase58(), oldDevKey.publicKey.toBase58());

    await program.methods
      .updateDevKey(payer.publicKey)
      .accounts({
        admin: oldAdmin.publicKey,
        dpr_config: configPDA,
      }).signers([oldAdmin]).rpc();

    await program.methods
      .updateAdmin(payer.publicKey)
      .accounts({
        admin: oldAdmin.publicKey,
        dpr_config: configPDA,
      }).signers([oldAdmin])
      .rpc();

    const configAccount2 = await program.account.config.fetch(configPDA);
    assert.equal(configAccount2.devKey.toBase58(), payer.publicKey.toBase58());
    assert.equal(configAccount2.admin.toBase58(), payer.publicKey.toBase58());
  });

  it("Creates credit account for user1 via setCredit", async () => {
    await program.methods
      .setCredit(0, new anchor.BN(100))
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
    assert.equal(creditAccount.credit.toString(), "100");
  });

  it("Updates user1's credit account via setCredit", async () => {
    await program.methods
      .setCredit(0, new anchor.BN(200))
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
    assert.equal(creditAccount.credit.toString(), "200");
  });

  it("Creates and sets credit account for user2 via setCredit", async () => {
    await program.methods
      .setCredit(0, new anchor.BN(300))
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
    assert.equal(creditAccount.credit.toString(), "300");
  });

  it("Fails to set credit as non-admin", async () => {
    await provider.connection.requestAirdrop(nonAdmin.publicKey, 1e9);
    await new Promise((resolve) => setTimeout(resolve, 1000));

    let error = null;
    try {
      await program.methods
        .setCredit(0, new anchor.BN(400))
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
    assert.equal(creditAccount.credit.toString(), "200"); // Still 200
  });

  it("credit_setting", async () => {
    const idx0 = 0;
    const idxBuffer = Buffer.alloc(2);
    idxBuffer.writeUInt16LE(0);

    const [settingsAccountPda0] = PublicKey.findProgramAddressSync(
      [Buffer.from("settings"), idxBuffer],
      program.programId);

    console.log("Settings Account PDA 0:", settingsAccountPda0.toBase58());

    const newSettings = [
      { dailyReward: new anchor.BN(0) },
      { dailyReward: new anchor.BN(1) },
      { dailyReward: new anchor.BN(2) },
    ];

    try {
      const tx = await program.methods
        .setSettings(idx0, newSettings)
        .accounts({
          settings_account: settingsAccountPda0,
          signer: payer.publicKey,
          system_program: anchor.web3.SystemProgram.programId,
        })
        .rpc({ commitment: "confirmed" });
      console.log("Set settings for account idx 0:", settingsAccountPda0.toBase58());
      const txInfo = await provider.connection.getTransaction(tx, {
        maxSupportedTransactionVersion: 0,
        commitment: "confirmed",
      });

      console.log("Transaction Logs:\n", txInfo?.meta?.logMessages?.join("\n"));

      await program.methods
        .addSetting(idx0, new anchor.BN(4))
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

      assert.equal(result.dailyReward.toString(), "2");

      await program.methods
        .updateSetting(idx0, 2, new anchor.BN(3))
        .accounts({
          settings_account: settingsAccountPda0,
          signer: payer.publicKey
        })
        .rpc({ commitment: "confirmed" });

      const result2 = await program.methods
        .getSetting(idx0, 2)
        .accounts({
          settings_account: settingsAccountPda0,
        })
        .view();
      console.log("Setting : ", result2);
      assert.equal(result2.dailyReward.toString(), "3");
    } catch (error) {
      console.error("Error sending transaction:", error);
    }

  });

  it("ed25519_verify_sysvar", async () => {
    const messageSigner = nacl.sign.keyPair.fromSecretKey(payer.payer.secretKey);
    const messageSignerPublicKey = Buffer.from(messageSigner.publicKey);
    const messageSignerSecretKey = Buffer.from(messageSigner.secretKey);

    //const message = Buffer.from("Sysvar verification test message", "utf-8");

    const coder = new BorshCoder(program.idl);
    const idx = 0;
    const idxBuffer = Buffer.alloc(2);
    idxBuffer.writeUInt16LE(idx);
    const history: DayCreditHistory = {
      history: [
        {campaign: idx, day: curDay()- 10, credit: 100 },
        { campaign:idx,day: curDay() + 10, credit: 200 },
      ],
    };
    const [settingsAccountPda0] = PublicKey.findProgramAddressSync(
      [Buffer.from("settings"), idxBuffer],
      program.programId);

    const message = coder.types.encode("dayCreditHistory", history);
    const signature = Buffer.from(nacl.sign.detached(message, messageSignerSecretKey));

    console.log("Message:", message.toString());
    console.log("Public Key (Buffer):", messageSignerPublicKey);
    console.log("Signature (Buffer):", signature);
    console.log("Signer (Wallet):", payer.publicKey.toBase58());

    // *** Create the Ed25519 Program instruction ***
    const ed25519Instruction = Ed25519Program.createInstructionWithPublicKey({
      publicKey: messageSignerPublicKey,
      message: message,
      signature: signature,
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
          signer: payer.publicKey,
          instructionSysvar: SYSVAR_INSTRUCTIONS_PUBKEY, // Pass the sysvar account ID
          creditInfo: creditPDA1,
          dprConfig: configPDA,
          settingsAccount: settingsAccountPda0,
        })
        .preInstructions([ed25519Instruction]) // *** Add Ed25519 ix *before* ours ***
        .rpc({ commitment: "confirmed" });

      console.log("Your transaction signature", tx);

      const txInfo = await provider.connection.getTransaction(tx, { commitment: "confirmed", maxSupportedTransactionVersion: 0 });
      console.log("Transaction Logs:\n", txInfo?.meta?.logMessages?.join("\n"));

      // expect(txInfo?.meta?.logMessages).to.include("Verification successful: Preceding Ed25519 instruction data matches arguments.");
      //expect(txInfo?.meta?.err).to.be.null;
      assert.equal(txInfo?.meta?.err, null);

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


//});

import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { DeeperSolana } from "../target/types/deeper_solana";
import { PublicKey, Keypair  } from '@solana/web3.js';
import assert from 'node:assert';


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
      const tx =  await program.methods
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

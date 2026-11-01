// CU Golf: página para jogar na BSC testnet. Sem build: ethers (UMD), sbpf-asm.js e este arquivo.
(() => {
  "use strict";
  const { ethers } = window;

  const CFG = {
    chainId: 97,
    chainHex: "0x61",
    rpc: "https://bsc-testnet-rpc.publicnode.com",
    explorer: "https://testnet.bscscan.com",
    golf: "0xb12C68f3e567A3eCEEc7eaf232d9f8CcfEc368ae",
    vm: "0xD9C7AF9165B190AdD2264853f2f6b4Aa4Bd6649F",
    token: "0xa5aA84562DfF099f8ba8F4FcD06Eb584de006dF8",
    board: "0x69D156d4523B68b09BEB02881f487949Ae6B7f3F",
    fromBlock: 140123800, // deploy do SbpfGolf
    logChunk: 45000,
  };

  const ROUND_T = "tuple(uint256 task,uint64 commitEnd,uint64 revealEnd,bytes32 seed,address best,uint64 bestCu,uint64 bestCommitBlock,uint256 prize,bool finalized,address topBidder,uint256 topBid,uint256 topChoice)";
  const GOLF_ABI = [
    "function round() view returns (uint256)",
    `function currentRound() view returns (${ROUND_T})`,
    "function taskName(uint256) view returns (string)",
    "function entryFee() view returns (uint256)",
    "function currentReward() view returns (uint256)",
    "function carry() view returns (uint256)",
    "function COMMIT_BLOCKS() view returns (uint64)",
    "function commits(uint256, address) view returns (bytes32 hash, uint64 blockNumber, bool revealed)",
    "function judge(uint256 task, bytes32 seed, bytes program) view returns (uint64)",
    "function commit(bytes32 hash)",
    "function reveal(bytes program, bytes32 salt) returns (uint64)",
    "function finalize()",
    "event Committed(uint256 indexed round, address indexed player, bytes32 hash)",
    "event Revealed(uint256 indexed round, address indexed player, uint64 totalCu, bool isBest, bytes program)",
    "event Finalized(uint256 indexed round, address indexed winner, uint64 cu, uint256 reward, uint256 prize)",
    "error NotCommitWindow()", "error NotRevealWindow()", "error RoundNotOver()", "error AlreadyFinalized()",
    "error AlreadyCommitted()", "error AlreadyRevealed()", "error NoCommit()", "error BadReveal()", "error ProgramTooLarge()",
    "error ProgramRejected(uint256 inputIndex, uint8 status, uint64 r0, uint64 expected)", "error BidTooLow(uint256 topBid)",
    "error InvalidChoice()", "error NothingToRefund()", "error SeedUnavailable()",
    "error ERC20InsufficientBalance(address sender, uint256 balance, uint256 needed)",
    "error ERC20InsufficientAllowance(address spender, uint256 allowance, uint256 needed)",
  ];
  const TOKEN_ABI = [
    "function balanceOf(address) view returns (uint256)",
    "function allowance(address, address) view returns (uint256)",
    "function approve(address, uint256) returns (bool)",
  ];
  const BOARD_ABI = [
    "function bounty(uint256) view returns (tuple(address poster,address rewardToken,uint256 reward,bytes refProgram,uint64 maxCu,uint32 inputLen,bytes[] edgeInputs,string spec,uint64 commitEnd,uint64 revealEnd,bytes32 seed,address best,uint64 bestCu,uint64 bestCommitBlock,bool finalized))",
  ];

  const TASKS = {
    0: { name: "fib", sig: "entrada: u64 n (0 a 255)  →  r0 = fib(n) mod 2⁶⁴, com fib(0)=0 e fib(1)=1" },
    1: { name: "popcount", sig: "entrada: u64 x  →  r0 = quantidade de bits 1 em x" },
    2: { name: "isqrt", sig: "entrada: u64 x  →  r0 = ⌊√x⌋" },
    3: { name: "max8", sig: "entrada: 8 × u64  →  r0 = o maior deles (sem sinal)" },
    4: { name: "gcd", sig: "entrada: u64 a, u64 b  →  r0 = mdc(a, b), com mdc(a, 0) = a" },
  };
  const STATUS = ["Ok", "programa inválido (o verificador recusou ou usou instrução proibida)", "divisão por zero",
    "acesso inválido à memória", "estourou o limite de 5.000 CU"];
  const ERRORS = {
    NotCommitWindow: "A janela de commit desta rodada já fechou.",
    NotRevealWindow: "Fora da janela de reveal.",
    RoundNotOver: "A rodada ainda não terminou.",
    AlreadyFinalized: "Esta rodada já foi fechada.",
    AlreadyCommitted: "Esta carteira já fez commit nesta rodada.",
    AlreadyRevealed: "Esta carteira já revelou nesta rodada.",
    NoCommit: "Esta carteira não fez commit nesta rodada.",
    BadReveal: "O programa ou o segredo não batem com o commit. Use o mesmo navegador do commit, ou o backup.",
    ProgramTooLarge: "Programa grande demais (máximo 256 instruções).",
    SeedUnavailable: "O hash do bloco de sorteio não está mais disponível.",
    ERC20InsufficientBalance: "GOLF insuficiente para a taxa de entrada.",
    ERC20InsufficientAllowance: "Falta autorizar o contrato a usar o seu GOLF.",
  };

  // ------------------------------------------------------------------ estado
  const rp = new ethers.JsonRpcProvider(CFG.rpc, CFG.chainId, { staticNetwork: ethers.Network.from(CFG.chainId) });
  const golfR = new ethers.Contract(CFG.golf, GOLF_ABI, rp);
  const tokenR = new ethers.Contract(CFG.token, TOKEN_ABI, rp);
  const S = {
    block: 0, spb: 0.45, round: 0n, r: null, fee: 0n, reward: 0n, carry: 0n, commitBlocks: 8000n,
    account: null, signer: null, chainOk: false, onchainCommit: null, busy: false,
    program: null, pastScanned: CFG.fromBlock - 1, past: [],
  };
  const $ = (id) => document.getElementById(id);

  // ------------------------------------------------------------------ utilidades
  const store = {
    get(k) { try { return JSON.parse(localStorage.getItem(k)); } catch { return null; } },
    set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* sem storage: segue sem lembrar */ } },
  };
  const short = (a) => a ? a.slice(0, 6) + "…" + a.slice(-4) : "";
  const fmtGolf = (wei) => {
    const s = ethers.formatEther(wei);
    const [i, d = ""] = s.split(".");
    const dd = d.replace(/0+$/, "").slice(0, 2);
    return Number(i).toLocaleString("pt-BR") + (dd ? "," + dd : "");
  };
  const fmtTime = (blocks) => {
    const s = Math.max(0, Math.round(blocks * S.spb));
    if (s < 90) return `~${s} s`;
    const m = Math.round(s / 60);
    if (m < 90) return `~${m} min`;
    return `~${Math.floor(m / 60)} h ${String(m % 60).padStart(2, "0")} min`;
  };
  const txLink = (h, label) => `<a href="${CFG.explorer}/tx/${h}" target="_blank" rel="noopener">${label}</a>`;
  let toastTimer;
  function toast(msg) {
    const t = $("toast");
    t.textContent = msg; t.hidden = false;
    clearTimeout(toastTimer); toastTimer = setTimeout(() => { t.hidden = true; }, 5000);
  }
  function show(el, kind, html) { el.hidden = false; el.dataset.kind = kind; el.innerHTML = html; }

  function explain(e) {
    const err = e?.error?.revert ? e.error : e;
    if (err?.code === "ACTION_REJECTED" || e?.info?.error?.code === 4001) return "Você cancelou na carteira.";
    if (err?.code === "INSUFFICIENT_FUNDS") return "Falta tBNB para pagar o gas. Pegue no faucet.";
    const rev = err?.revert || tryDecode(err);
    if (rev) {
      if (rev.name === "ProgramRejected") return rejectText(rev.args);
      if (ERRORS[rev.name]) return ERRORS[rev.name];
      return `O contrato recusou: ${rev.name}`;
    }
    return (err?.shortMessage || err?.message || String(e)).slice(0, 300);
  }
  function tryDecode(err) {
    const data = err?.data || err?.info?.error?.data?.data || err?.info?.error?.data;
    if (typeof data !== "string" || data.length < 10) return null;
    try { const d = golfR.interface.parseError(data); return d && { name: d.name, args: d.args }; } catch { return null; }
  }
  function rejectText(a) {
    const k = BigInt(a[0]), st = Number(a[1]);
    if (k === ethers.MaxUint256) return "Nenhuma entrada válida para conferir.";
    if (st !== 0) return `Falhou na entrada ${Number(k) + 1} de 4: ${STATUS[st] || "status " + st}.`;
    return `Resposta errada na entrada ${Number(k) + 1} de 4: devolveu ${a[2]} (0x${BigInt(a[2]).toString(16)}), o certo é ${a[3]} (0x${BigInt(a[3]).toString(16)}).`;
  }

  // ------------------------------------------------------------------ editor e assembler
  function assemble() {
    const src = $("src").value;
    const lines = src.split(/\r\n|\n|\r/);
    const kept = [];
    lines.forEach((l, i) => { if (l.split(";")[0].trim() !== "") kept.push(i + 1); });
    const st = $("asmStatus");
    try {
      const bytes = window.sbpfAssemble(src);
      if (bytes.length === 0) throw new Error("O programa está vazio.");
      const n = bytes.length / 8;
      S.program = ethers.hexlify(bytes);
      st.className = "asm-status ok";
      st.innerHTML = `<b>${n}</b> instruç${n === 1 ? "ão" : "ões"} · ${bytes.length} bytes` +
        (n > 256 ? ` · <span style="color:var(--bad)">acima do limite de 256</span>` : "") +
        ` · <span title="${S.program}">${S.program.slice(0, 26)}…</span>`;
    } catch (e) {
      S.program = null;
      st.className = "asm-status err";
      st.textContent = e.message.replace(/line (\d+)/, (_, n) => `linha ${kept[Number(n) - 1] ?? n}`).replace(/column/, "coluna");
    }
    updateSteps();
  }
  function draftKey() { return `cugolf:draft:${S.r ? S.r.task : "x"}`; }
  function loadExample(force) {
    if (!S.r) return;
    const t = TASKS[Number(S.r.task)];
    const ex = t && window.CU_GOLF_EXAMPLES?.[t.name];
    const draft = store.get(draftKey());
    $("src").value = !force && draft ? draft : ex || "; escreva aqui o seu programa\n    mov64 r0, 0\n    exit\n";
    assemble();
  }

  async function runTest() {
    const out = $("testResult");
    if (!S.program) return show(out, "bad", "Corrija o programa antes de testar.");
    if (!S.r) return;
    const btn = $("testBtn"); btn.disabled = true;
    show(out, "info", "Rodando no contrato com 3 sorteios de 4 entradas…");
    try {
      const res = [];
      for (let i = 0; i < 3; i++) {
        const seed = ethers.hexlify(ethers.randomBytes(32));
        res.push(await golfR.judge(S.r.task, seed, S.program));
      }
      const nums = res.map(Number);
      const avg = Math.round(nums.reduce((a, b) => a + b, 0) / nums.length);
      const par = S.r.best !== ethers.ZeroAddress ? Number(S.r.bestCu) : null;
      let cmp = "";
      if (par !== null) cmp = avg < par ? `<span style="color:var(--ok)">abaixo do par atual (${par})</span>` : `par atual: ${par}`;
      show(out, "ok", `<div class="big">${avg} CU</div><div>média de 3 sorteios (${nums.join(", ")}). Respostas certas em todas as entradas. ${cmp}</div>` +
        `<div class="mono">No reveal vale um sorteio só, feito pelo hash do bloco.</div>`);
    } catch (e) {
      show(out, "bad", explain(e));
    } finally { btn.disabled = false; }
  }

  // ------------------------------------------------------------------ carteira
  async function connect() {
    if (!window.ethereum) {
      show($("playResult"), "info", `Nenhuma carteira encontrada neste navegador. Instale a <a href="https://metamask.io/download/" target="_blank" rel="noopener">MetaMask</a> e recarregue a página.`);
      return;
    }
    try {
      const bp = new ethers.BrowserProvider(window.ethereum, "any");
      const accs = await bp.send("eth_requestAccounts", []);
      await ensureChain();
      S.account = ethers.getAddress(accs[0]);
      S.signer = await new ethers.BrowserProvider(window.ethereum, "any").getSigner(S.account);
      await refreshAccount();
    } catch (e) { toast(explain(e)); }
  }
  async function ensureChain() {
    const id = await window.ethereum.request({ method: "eth_chainId" });
    if (id === CFG.chainHex) { S.chainOk = true; return; }
    try {
      await window.ethereum.request({ method: "wallet_switchEthereumChain", params: [{ chainId: CFG.chainHex }] });
    } catch (e) {
      if (e.code !== 4902 && e?.data?.originalError?.code !== 4902) throw e;
      await window.ethereum.request({ method: "wallet_addEthereumChain", params: [{
        chainId: CFG.chainHex, chainName: "BNB Smart Chain Testnet",
        nativeCurrency: { name: "tBNB", symbol: "tBNB", decimals: 18 }, rpcUrls: [CFG.rpc], blockExplorerUrls: [CFG.explorer],
      }] });
    }
    S.chainOk = (await window.ethereum.request({ method: "eth_chainId" })) === CFG.chainHex;
  }
  async function refreshAccount() {
    if (!S.account) return;
    const [bnb, golf, c] = await Promise.all([rp.getBalance(S.account), tokenR.balanceOf(S.account), golfR.commits(S.round, S.account)]);
    S.onchainCommit = c;
    $("youPanel").hidden = false;
    $("youAddr").innerHTML = `<a href="${CFG.explorer}/address/${S.account}" target="_blank" rel="noopener">${S.account}</a>`;
    $("youBnb").textContent = Number(ethers.formatEther(bnb)).toLocaleString("pt-BR", { maximumFractionDigits: 4 });
    $("youGolf").textContent = fmtGolf(golf);
    $("connectBtn").textContent = short(S.account);
    $("netChip").textContent = S.chainOk ? "BSC testnet" : "rede errada";
    $("netChip").className = S.chainOk ? "chip live" : "chip";
    updateSteps();
  }
  function saveKey() { return `cugolf:${CFG.golf}:${S.round}:${S.account}`.toLowerCase(); }

  async function send(fn, label) {
    const out = $("playResult");
    S.busy = true; updateSteps();
    try {
      if (!S.chainOk) await ensureChain();
      show(out, "info", `${label}: confirme na carteira…`);
      const tx = await fn();
      show(out, "info", `${label}: aguardando o bloco… ${txLink(tx.hash, "ver transação")}`);
      const rc = await tx.wait();
      return rc;
    } catch (e) {
      show(out, "bad", explain(e));
      return null;
    } finally { S.busy = false; await refresh(); }
  }

  async function doCommit() {
    if (!S.program) return;
    const out = $("playResult");
    // não deixa pagar para entrar com um programa que já falha
    try { await golfR.judge(S.r.task, ethers.hexlify(ethers.randomBytes(32)), S.program); }
    catch (e) { return show(out, "bad", "O programa falhou no teste: " + explain(e) + " Corrija antes de enviar."); }
    const golf = golfR.connect(S.signer);
    if (S.fee > 0n) {
      const tok = tokenR.connect(S.signer);
      const [bal, allow] = await Promise.all([tokenR.balanceOf(S.account), tokenR.allowance(S.account, CFG.golf)]);
      if (bal < S.fee) return show(out, "bad", `A entrada desta rodada custa ${fmtGolf(S.fee)} GOLF e você tem ${fmtGolf(bal)}.`);
      if (allow < S.fee && !(await send(() => tok.approve(CFG.golf, S.fee), "Autorizar GOLF"))) return;
    }
    const salt = ethers.hexlify(ethers.randomBytes(32));
    const hash = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
      ["address", "uint256", "bytes32", "bytes32"], [S.account, S.round, ethers.keccak256(S.program), salt]));
    const saved = { round: S.round.toString(), account: S.account, program: S.program, salt, source: $("src").value, contract: CFG.golf };
    store.set(saveKey(), saved); // antes da transação: o segredo não pode se perder
    const rc = await send(() => golf.commit(hash), "Commit");
    if (rc) {
      show(out, "ok", `Commit enviado. Volte quando a janela de reveal abrir (${fmtTime(Number(S.r.commitEnd) - S.block)}). ${txLink(rc.hash, "ver transação")}`);
      toast("Commit enviado");
    }
  }

  async function doReveal() {
    const saved = store.get(saveKey());
    if (!saved) return show($("playResult"), "bad", "Não achei o segredo deste commit neste navegador. Use o navegador do commit.");
    const rc = await send(() => golfR.connect(S.signer).reveal(saved.program, saved.salt), "Reveal");
    if (rc) {
      const ev = rc.logs.map((l) => { try { return golfR.interface.parseLog(l); } catch { return null; } }).find((x) => x?.name === "Revealed");
      const cu = ev ? ev.args.totalCu : "?";
      show($("playResult"), "ok", `<div class="big">${cu} CU</div><div>${ev?.args.isBest ? "Você é o melhor da rodada até agora." : "Revelado. Ainda tem alguém com menos CU."} ${txLink(rc.hash, "ver transação")}</div>`);
      toast("Programa revelado");
    }
  }

  async function doFinalize() {
    const rc = await send(() => golfR.connect(S.signer).finalize(), "Fechar rodada");
    if (rc) {
      const ev = rc.logs.map((l) => { try { return golfR.interface.parseLog(l); } catch { return null; } }).find((x) => x?.name === "Finalized");
      const w = ev && ev.args.winner !== ethers.ZeroAddress ? `${short(ev.args.winner)} venceu com ${ev.args.cu} CU e levou ${fmtGolf(ev.args.reward + ev.args.prize)} GOLF.` : "Ninguém revelou; o prêmio passa para a próxima.";
      show($("playResult"), "ok", `Rodada fechada. ${w} ${txLink(rc.hash, "ver transação")}`);
      S.pastScanned = Math.min(S.pastScanned, S.block - 200);
      loadPast();
    }
  }

  // ------------------------------------------------------------------ leitura da rodada
  function phase() {
    if (!S.r) return "load";
    if (S.block <= Number(S.r.commitEnd)) return "commit";
    if (S.block <= Number(S.r.revealEnd)) return "reveal";
    return "over";
  }

  async function refresh() {
    try {
      const [block, round, r, fee, reward, carry] = await Promise.all([
        rp.getBlockNumber(), golfR.round(), golfR.currentRound(), golfR.entryFee(), golfR.currentReward(), golfR.carry()]);
      const taskChanged = !S.r || S.r.task !== r.task || S.round !== round;
      Object.assign(S, { block, round, r, fee, reward, carry });
      $("blockChip").textContent = `bloco ${block.toLocaleString("pt-BR")}`;
      $("roundNo").textContent = round.toString();
      const t = TASKS[Number(r.task)];
      if (t) { $("taskName").textContent = t.name; $("taskSig").textContent = t.sig; }
      else if (r.task >= 1000n) {
        $("taskName").textContent = `bounty #${r.task - 1000n}`;
        new ethers.Contract(CFG.board, BOARD_ABI, rp).bounty(r.task - 1000n)
          .then((b) => { $("taskSig").textContent = `${b.spec} · entrada: ${b.inputLen} bytes aleatórios · correção pelo programa de referência`; })
          .catch(() => {});
      }
      const p = phase(), pill = $("phasePill"), timer = $("phaseTimer");
      if (p === "commit") { pill.textContent = "Commit aberto"; pill.className = "pill commit"; timer.textContent = `fecha em ${fmtTime(Number(r.commitEnd) - block)} · bloco ${r.commitEnd}`; }
      else if (p === "reveal") { pill.textContent = "Reveal aberto"; pill.className = "pill reveal"; timer.textContent = `fecha em ${fmtTime(Number(r.revealEnd) - block)} · bloco ${r.revealEnd}`; }
      else { pill.textContent = "Esperando fechar"; pill.className = "pill over"; timer.textContent = "qualquer pessoa pode fechar a rodada"; }
      const has = r.best !== ethers.ZeroAddress;
      $("parCu").textContent = has ? r.bestCu.toString() : "—";
      $("parWho").textContent = has ? short(r.best) : "ninguém revelou";
      $("prize").textContent = fmtGolf(reward + r.prize + carry);
      $("prizeNote").textContent = r.prize + carry > 0n ? `GOLF (${fmtGolf(reward)} novos + ${fmtGolf(r.prize + carry)} de taxas)` : "GOLF novos";
      $("fee").textContent = fee === 0n ? "grátis" : fmtGolf(fee);
      $("feeNote").textContent = fee === 0n ? "rodadas iniciais" : "GOLF, metade queimada";
      if (taskChanged) { loadExample(false); loadBoard(); }
      if (S.account) await refreshAccount(); else updateSteps();
    } catch (e) {
      $("blockChip").textContent = "sem conexão com a rede";
      console.error(e);
    }
  }

  async function loadBoard() {
    if (!S.r) return;
    const start = Number(S.r.commitEnd - S.commitBlocks);
    try {
      const [revs, coms] = await Promise.all([
        golfR.queryFilter(golfR.filters.Revealed(S.round), start, "latest"),
        golfR.queryFilter(golfR.filters.Committed(S.round), start, "latest")]);
      const rows = revs.map((l) => ({ who: l.args.player, cu: Number(l.args.totalCu) })).sort((a, b) => a.cu - b.cu);
      $("boardBody").innerHTML = rows.map((x) => `<tr class="${x.who === S.r.best ? "best" : ""}"><td class="addr"><a href="${CFG.explorer}/address/${x.who}" target="_blank" rel="noopener">${short(x.who)}</a>${S.account && x.who === S.account ? '<span class="you">você</span>' : ""}</td><td class="cu">${x.cu}</td></tr>`).join("");
      $("boardTable").hidden = rows.length === 0;
      $("boardEmpty").hidden = rows.length > 0;
      $("commitCount").textContent = `${coms.length} commit${coms.length === 1 ? "" : "s"} nesta rodada, ${rows.length} revelado${rows.length === 1 ? "" : "s"}.`;
    } catch (e) { console.error(e); }
  }

  async function loadPast() {
    try {
      const head = await rp.getBlockNumber();
      while (S.pastScanned < head) {
        const to = Math.min(head, S.pastScanned + CFG.logChunk);
        const logs = await golfR.queryFilter(golfR.filters.Finalized(), S.pastScanned + 1, to);
        for (const l of logs) if (!S.past.some((p) => p.round === l.args.round)) S.past.push({ round: l.args.round, winner: l.args.winner, cu: l.args.cu, total: l.args.reward + l.args.prize });
        S.pastScanned = to;
      }
      S.past.sort((a, b) => (a.round < b.round ? 1 : -1));
      const rows = S.past.slice(0, 12);
      $("pastBody").innerHTML = rows.map((p) => {
        const t = p.winner === ethers.ZeroAddress;
        return `<tr><td>${p.round}</td><td class="addr">${t ? "sem vencedor" : `<a href="${CFG.explorer}/address/${p.winner}" target="_blank" rel="noopener">${short(p.winner)}</a> · ${fmtGolf(p.total)} GOLF`}</td><td class="cu">${t ? "—" : p.cu}</td></tr>`;
      }).join("");
      $("pastTable").hidden = rows.length === 0;
      $("pastEmpty").hidden = rows.length > 0;
    } catch (e) { console.error(e); }
  }

  function updateSteps() {
    const p = phase();
    const connected = !!S.account && S.chainOk;
    const c = S.onchainCommit;
    const committed = !!c && c.hash !== ethers.ZeroHash;
    const revealed = committed && c.revealed;
    const saved = S.account ? store.get(saveKey()) : null;
    const mark = (id, state) => { $(id).className = state; };
    mark("stepWallet", connected ? "done" : "now");
    mark("stepCommit", committed ? "done" : connected && p === "commit" ? "now" : "");
    mark("stepReveal", revealed ? "done" : committed && p === "reveal" ? "now" : "");
    mark("stepFinal", p === "over" ? "now" : "");
    $("commitBtn").disabled = S.busy || !connected || p !== "commit" || committed || !S.program;
    $("revealBtn").disabled = S.busy || !connected || p !== "reveal" || !committed || revealed || !saved;
    $("finalizeBtn").disabled = S.busy || !connected || p !== "over";
    $("commitBtn").textContent = committed ? "Commit feito" : S.fee > 0n ? `Enviar commit (${fmtGolf(S.fee)} GOLF)` : "Enviar commit";
    const box = $("backupBox");
    if (saved && !revealed) { box.hidden = false; $("backupText").textContent = JSON.stringify(saved, null, 1); }
    else box.hidden = true;
  }

  async function measureBlockTime() {
    try {
      const n = await rp.getBlockNumber();
      const [a, b] = await Promise.all([rp.getBlock(n - 2000), rp.getBlock(n)]);
      const spb = (b.timestamp - a.timestamp) / 2000;
      if (spb > 0.1 && spb < 10) S.spb = spb;
    } catch { /* fica 0,45 s */ }
  }

  // ------------------------------------------------------------------ início
  function wire() {
    $("lnkGolf").href = `${CFG.explorer}/address/${CFG.golf}`;
    $("lnkVm").href = `${CFG.explorer}/address/${CFG.vm}`;
    $("lnkToken").href = `${CFG.explorer}/address/${CFG.token}`;
    let t;
    $("src").addEventListener("input", () => {
      clearTimeout(t);
      t = setTimeout(() => { assemble(); store.set(draftKey(), $("src").value); }, 150);
    });
    $("src").addEventListener("keydown", (e) => {
      if (e.key === "Tab" && !e.shiftKey && !e.altKey && !e.ctrlKey && !e.metaKey) {
        e.preventDefault();
        const el = e.target, s = el.selectionStart;
        el.setRangeText("    ", s, el.selectionEnd, "end");
        el.dispatchEvent(new Event("input"));
      }
    });
    $("exampleBtn").addEventListener("click", () => loadExample(true));
    $("testBtn").addEventListener("click", runTest);
    $("connectBtn").addEventListener("click", connect);
    $("commitBtn").addEventListener("click", doCommit);
    $("revealBtn").addEventListener("click", doReveal);
    $("finalizeBtn").addEventListener("click", doFinalize);
    $("copyBackup").addEventListener("click", () => {
      const txt = $("backupText").textContent;
      navigator.clipboard?.writeText(txt).then(() => toast("Backup copiado"), () => {
        const r = document.createRange(); r.selectNodeContents($("backupText"));
        const sel = getSelection(); sel.removeAllRanges(); sel.addRange(r); toast("Selecionado: copie com Ctrl+C");
      });
    });
    $("watchToken").addEventListener("click", () => {
      window.ethereum?.request({ method: "wallet_watchAsset", params: { type: "ERC20", options: { address: CFG.token, symbol: "GOLF", decimals: 18 } } }).catch(() => {});
    });
    if (window.ethereum?.on) {
      window.ethereum.on("accountsChanged", (a) => { S.account = a[0] ? ethers.getAddress(a[0]) : null; if (S.account) connect(); else location.reload(); });
      window.ethereum.on("chainChanged", () => location.reload());
    }
  }

  async function start() {
    wire();
    golfR.COMMIT_BLOCKS().then((v) => { S.commitBlocks = v; }).catch(() => {});
    await measureBlockTime();
    await refresh();
    loadPast();
    // reconecta sem pop-up se a carteira já autorizou esta página
    if (window.ethereum) {
      window.ethereum.request({ method: "eth_accounts" }).then((a) => { if (a && a[0]) connect(); }).catch(() => {});
    }
    setInterval(refresh, 6000);
    setInterval(loadBoard, 15000);
    setInterval(loadPast, 60000);
  }
  start();
})();

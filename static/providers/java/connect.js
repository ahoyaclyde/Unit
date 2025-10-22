async function postConnect(address, provider='manual', username='', meta={}){
  const res = await fetch('/api/connect', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({address, provider, username, meta})
  });
  const j = await res.json();
  if (j.session_token){
    window.location = '/dashboard';
  } else {
    alert('Connect failed');
  }
}

async function doChallengeAndVerify(address, provider='manual'){
  const chal = await fetch('/api/challenge', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({address})});
  const chalj = await chal.json();
  const message = chalj.message;
  const session_token = chalj.session_token;
  if (!window.ethereum) { alert('MetaMask not found'); return; }
  const providerWin = new ethers.providers.Web3Provider(window.ethereum);
  const signer = providerWin.getSigner();
  const signature = await signer.signMessage(message);
  const ver = await fetch('/api/verify', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({address, signature, session_token})});
  const verj = await ver.json();
  if (verj.status === 'verified'){
    await postConnect(address, provider, '', {verified: true});
  } else {
    alert('Verification failed: ' + JSON.stringify(verj));
  }
}

async function connectWithMetaMask(chain){
  try {
    await window.ethereum.request({ method: 'eth_requestAccounts' });
    const provider = new ethers.providers.Web3Provider(window.ethereum);
    const signer = provider.getSigner();
    const address = await signer.getAddress();
    await doChallengeAndVerify(address, 'injected');
  } catch (e) { console.error(e); alert('MetaMask connect failed'); }
}

async function connectWithWalletConnect(chain){
  const projectId = window.WC_PROJECT_ID || 'walletconnect';
  const modal = new window.Web3Modal.default({ projectId: projectId, standaloneChains: ['eip155:1'] });
  try{
    const session = await modal.open();
    const address = session.accounts && session.accounts[0] ? session.accounts[0].split(':')[2] : null;
    if (address){
      const chal = await fetch('/api/challenge', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({address})});
      const chalj = await chal.json();
      const message = chalj.message; const session_token = chalj.session_token;
      const wcProvider = new ethers.providers.Web3Provider(session.provider);
      const signer = wcProvider.getSigner();
      const signature = await signer.signMessage(message);
      const ver = await fetch('/api/verify', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({address, signature, session_token})});
      const verj = await ver.json();
      if (verj.status === 'verified'){
        await postConnect(address, 'walletconnect', '', {chain: chain});
      } else { alert('Verification failed'); }
    }
  }catch(err){ console.error(err); alert('WalletConnect failed: '+err); }
}

document.addEventListener('DOMContentLoaded', ()=>{
  document.getElementById('themeBtn').addEventListener('click', ()=>{ document.body.classList.toggle('dark'); });
  document.querySelectorAll('.chain-card').forEach(card=>{ card.addEventListener('click', ()=>{ const chain = card.getAttribute('data-chain'); if (chain === 'ethereum'){ if (window.ethereum) connectWithMetaMask(chain); else connectWithWalletConnect(chain); } else { connectWithWalletConnect(chain); } }); });
});

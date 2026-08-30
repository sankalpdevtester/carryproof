(() => {
  const guide = document.getElementById('judgeGuide');
  const layout = document.querySelector('.demo-layout');
  const title = document.getElementById('guideTitle');
  const action = document.getElementById('guideAction');
  const outcome = document.getElementById('guideOutcome');
  const previous = document.getElementById('guidePrevious');
  const next = document.getElementById('guideNext');
  const openButton = document.getElementById('openGuide');
  const steps = [
    {
      title: 'A handoff that carries its own proof',
      description: 'The sender prepares a folder once. The receiver gets the files, a record of changes, and an integrity verifier in one HTML file. No receiver app to install.',
      detail: 'This is a public, synthetic sample. No login, access code, or upload is needed. Inspection and preparation already ran locally with the Python tool.',
      action: 'Show the sample files',
      target: 'files',
    },
    {
      title: 'See what changed, and what did not',
      description: 'Three sample files were changed: image metadata was removed and an Office fixture had its active content stripped. Original and prepared hashes appear in the change record.',
      detail: 'The score falls from 75 to 5, not zero. The text note still has identifiers and the duplicate files remain. Use Before / after in the top bar for the full report.',
      action: 'Show recorded changes',
      target: 'ledger',
    },
    {
      title: 'Recompute every fingerprint',
      description: 'Verify the manifest and all six embedded files in your browser. These are actual payload bytes, checked with SHA-256 by the same verifier used for downloads.',
      detail: 'A matching result means these bytes agree with their manifest. It does not certify that the files are safe or identify the sender.',
      action: 'Verify all six files',
      run: async () => verifyAll(),
    },
    {
      title: 'Change one byte. Watch it fail.',
      description: 'The demo flips a bit in an in-memory copy of a real payload and sends it through the same comparison. SHA-256 must reject the changed bytes.',
      detail: 'The embedded files are never changed. This is a real corruption check, not a prerecorded animation or a simulated verdict.',
      action: 'Run the one-byte test',
      run: async () => testOneByteChange(),
    },
    {
      title: 'Download only after verification',
      description: 'Extract the small text sample below. The manifest and this file are checked again before the browser releases the download.',
      detail: 'The download section also has the complete offline capsule and Python executable. Run the CLI locally for scanning, sanitizing, ZIP verification, recovery, and LAN sharing.',
      action: 'Verify & download text sample',
      run: async () => {
        const index = manifest.files.findIndex(file => file.path === 'duplicate-a.txt');
        if (index < 0) throw new Error('The text sample is missing.');
        await downloadFile(index);
      },
    },
  ];
  let current = 0;
  let busy = false;
  const results = new Map();

  function setVisible(visible) {
    guide.hidden = !visible;
    layout.classList.toggle('guide-hidden', !visible);
    openButton.setAttribute('aria-expanded', String(visible));
    if (visible) {
      guide.scrollIntoView({block: 'start'});
      title.focus({preventScroll: true});
    } else {
      openButton.focus({preventScroll: true});
    }
  }

  function renderStep(focus = true) {
    const step = steps[current];
    title.textContent = step.title;
    document.getElementById('guideDescription').textContent = step.description;
    document.getElementById('guideDetail').textContent = step.detail;
    action.textContent = step.action;
    action.disabled = busy;
    previous.disabled = busy || current === 0;
    next.disabled = busy;
    next.textContent = current === steps.length - 1 ? 'Finish' : 'Next';
    document.getElementById('guideCount').textContent = `${current + 1} of ${steps.length}`;
    document.querySelectorAll('[data-step]').forEach(button => {
      button.disabled = busy;
      if (Number(button.dataset.step) === current) button.setAttribute('aria-current', 'step');
      else button.removeAttribute('aria-current');
    });
    const result = results.get(current);
    outcome.textContent = result?.text || '';
    outcome.classList.toggle('failed', result?.failed || false);
    document.querySelectorAll('.tour-target').forEach(element => element.classList.remove('tour-target'));
    if (focus) title.focus({preventScroll: true});
  }

  function syncChecks() {
    const message = document.getElementById('verificationMessage').textContent;
    if (message.startsWith('Manifest and all ')) {
      const check = document.getElementById('guideVerified');
      check.textContent = 'All six files: verified';
      check.className = 'passed';
    }
    if (message.startsWith('One-byte change rejected')) {
      const check = document.getElementById('guideTampered');
      check.textContent = 'One-byte test: rejected';
      check.className = 'passed';
    }
  }

  action.addEventListener('click', async () => {
    if (busy) return;
    const step = steps[current];
    if (step.target) {
      const target = document.getElementById(step.target);
      target.classList.add('tour-target');
      target.scrollIntoView({block: 'center'});
      return;
    }
    if (document.getElementById('verifyAll').disabled) return;
    busy = true;
    renderStep(false);
    outcome.textContent = 'Checking the actual embedded bytes...';
    try {
      await step.run();
      const status = document.getElementById('verificationMessage');
      results.set(current, {text: status.textContent, failed: status.classList.contains('failed')});
      syncChecks();
    } catch (error) {
      results.set(current, {text: error.message, failed: true});
    } finally {
      busy = false;
      renderStep(false);
    }
  });
  previous.addEventListener('click', () => {
    if (!busy && current > 0) { current--; renderStep(); }
  });
  next.addEventListener('click', () => {
    if (busy) return;
    if (current === steps.length - 1) setVisible(false);
    else { current++; renderStep(); }
  });
  document.querySelectorAll('[data-step]').forEach(button => button.addEventListener('click', () => {
    if (!busy) { current = Number(button.dataset.step); renderStep(); }
  }));
  document.getElementById('closeGuide').addEventListener('click', () => setVisible(false));
  openButton.addEventListener('click', () => {
    if (!busy) { current = 0; renderStep(false); }
    setVisible(true);
  });
  guide.addEventListener('keydown', event => {
    if (event.key === 'Escape') setVisible(false);
  });
  new MutationObserver(syncChecks).observe(document.getElementById('verificationMessage'), {
    childList: true, characterData: true, subtree: true,
  });
  renderStep(false);
})();

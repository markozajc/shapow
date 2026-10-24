//SPDX-License-Identifier: AGPL-3.0-only
(function () {
	const progressElement = document.getElementById("progress");
	const logElement = document.getElementById("log");

	function createLine(text) {
		const line = document.createElement("li");
		line.textContent = text;
		return line;
	}

	function estimateIterations(difficulty) {
		// estimate is the 90th percentile for the number of iterations required to chance upon N (= difficulty)
		// consecutive zeroes

		if (difficulty <= 13) return 25_000; // we don't report iterations below 25k, and difficulty=13 computes to 18_862

		// these values are memoized results of the formula in the else branch
		// [...Array(16).keys()].map(i => i + 14).map(i => Math.round(Math.log(0.1) / Math.log(1 - Math.pow(0.5, i))));
		// this is the solution for (1 - 0.5^difficulty)^x = 1 - 0.9
		return (
			[
				37_724, // 14
				75_450, // 15
				150_901, // 16
				301_803, // 17
				603_608, // 18
				1_207_217, // 19
				2_414_434, // 20
				4_828_870, // 21
				9_657_741, // 22
				19_315_483, // 23
				38_630_966, // 24
				77_261_934, // 25
				154_523_869, // 26
				309_047_739, // 27
				618_095_478, // 28
				1_236_190_958, // 29
			][difficulty - 14] || Math.round(Math.log(0.1) / Math.log(1 - Math.pow(0.5, difficulty)))
		);
	}

	logElement.innerHTML = "";

	try {
		document.body.classList.add("started");

		logElement.appendChild(
			createLine(
				`Solving challenge with difficulty ${difficulty}, ${serverData.length / 2} bytes of server data`,
			),
		);

		if (Date.now() - (sessionStorage?.getItem("shapow-last-solve-time") ?? 0) < 1000 /* 1 second */) {
			document.body.classList.add("error");
			logElement.appendChild(
				createLine("Server-side error, avoiding a reload loop. Contact site's administrators."),
			);
		} else {
			const iterLine = createLine(`Waiting for worker...`);
			logElement.appendChild(iterLine);

			const estimateIter = estimateIterations(difficulty);
			const worker = new Worker("shapow_internal/challenge-worker.js");
			worker.onmessage = (m) => {
				if (m.data[0] === 0) {
					// update iteration
					progressElement.value = Math.min(0.95, m.data[1] / estimateIter);
					iterLine.textContent = `Iteration ${m.data[1]}: ${m.data[2]} (unsolved)`;
				} else if (m.data[0] === 1) {
					// error
					progressElement.value = 1;
					document.body.classList.add("error");
					logElement.appendChild(createLine(`Error in worker: ${m.data[1]}`));
				} else if (m.data[0] === 2) {
					// solved
					progressElement.value = 1;
					document.body.classList.add("done");
					iterLine.textContent = `Iteration ${m.data[1]}: ${m.data[2].substr(m.data[2].length - nonceLength * 2)} (solved)`;
					logElement.appendChild(createLine(`Success! You will be redirected shortly.`));

					const url = new URL(location.href);
					url.searchParams.set("shapow-response", m.data[2]);

					sessionStorage?.setItem("shapow-last-solve-time", Date.now());
					document.location.replace(url.href);
				} else {
					console.error(`Unknown message: ${m.data}`);
				}
			};

			worker.postMessage([difficulty, serverData, nonceLength]);
		}
	} catch (e) {
		console.error(e);
		progressElement.value = 1;
		document.body.classList.add("error");
		logElement.appendChild(createLine(`Error in script: ${e.toString()}`));
	}
})();

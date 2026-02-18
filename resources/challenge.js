//SPDX-License-Identifier: AGPL-3.0-only
const progressElement = document.getElementById("progress");
const logElement = document.getElementById("log");

function createLine(text) {
	const line = document.createElement("li");
	line.textContent = text;
	return line;
}

function estimateIterations(difficulty) {
	// sampled as 90th percentile from ~500 solutions per difficulty (fewer for higher difficulties)
	if (difficulty < 9) return 1000;
	else if (difficulty == 9) return 2000;
	else if (difficulty == 10) return 3000;
	else if (difficulty == 11) return 5000;
	else if (difficulty == 12) return 9000;
	else if (difficulty == 13) return 18000;
	else if (difficulty == 14) return 35000;
	else if (difficulty == 15) return 68000;
	else if (difficulty == 16) return 140000;
	else if (difficulty == 17) return 320000;
	else if (difficulty == 18) return 547000;
	else if (difficulty == 19) return 1301000;
	else if (difficulty == 20) return 1907000;
	else return -50 + 20 * difficulty + Math.pow(2.1, difficulty); // rough curve, but you should not increase the
																   // difficulty past 20
}


logElement.innerHTML = '';
document.body.classList.add("started");

logElement.appendChild(createLine(
	`Solving challenge with difficulty ${difficulty}, ${serverData.length/2} bytes of server data`));

const iterLine = createLine(`Waiting for worker...`);
logElement.appendChild(iterLine);

const estimateIter = estimateIterations(difficulty);
const worker = new Worker("shapow_internal/challenge-worker.js");
worker.onmessage = m => {
	if (m.data[0] == 0) { // update iteration
		progressElement.value = Math.min(0.95, m.data[1] / estimateIter);
		iterLine.textContent = `Iteration ${m.data[1]}: ${m.data[2]} (unsolved)`;

	} else if (m.data[0] == 1) { // error
		progressElement.value = 0;
		document.body.classList.add("error");
		logElement.appendChild(createLine(`Error! ${m.data[1]}`));

	} else if (m.data[0] == 2) { // solved
		// TODO redirect
		progressElement.value = 1;
		document.body.classList.add("done");
		iterLine.textContent = `Iteration ${m.data[1]}: ${m.data[2].substr(m.data[2].length - nonceLength * 2)} (solved)`;
		logElement.appendChild(createLine(`Success! You will be redirected shortly.`));

		const url = new URL(window.location.href);
		url.searchParams.set("shapow-response", m.data[2]);
		document.location.replace(url.href);

	} else {
		console.error(`Unknown message: ${m.data}`)
	}
};

worker.postMessage([difficulty, serverData, nonceLength]);

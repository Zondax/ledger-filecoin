import Zemu from "@zondax/zemu";
import FilecoinApp from "@zondax/ledger-filecoin";
import path from "path";

const APP_PATH = path.resolve(`./../../app/bin/app.elf`);

const seed = "equip will roof matter pink blind book anxiety banner elbow sun young"
const SIM_OPTIONS = {
    logging: true,
    start_delay: 4000,
    X11: true,
    custom: `-s "${seed}" --color LAGOON_BLUE`
};

async function beforeStart() {
    process.on("SIGINT", () => {
        Zemu.default.stopAllEmuContainers(function () {
            process.exit();
        });
    });
    await Zemu.default.checkAndPullImage();
}

async function beforeEnd() {
    await Zemu.default.stopAllEmuContainers();
}

async function debugScenario(sim, app) {
    // Here you can customize what you want to do :)

    const path = "m/44'/461'/0'/0/1";
    const txBlob = Buffer.from(
        "890055026d21137eb4c4814269e894d296cf6500e43cd7145502e0c7c75f82d55e5ed55db28033630df4274a984f0144000186a0430009c41961a80040",
        "hex",
    );

    const signatureRequest = await app.sign(path, txBlob);
    const signatureResponse = signatureRequest;
    console.log(signatureResponse)
}

async function debugScenario2(sim, app) {
    await Zemu.default.sleep(20000);

    // const response = await app.getVersion();
    // console.log(response)
}

async function main() {
    await beforeStart();

    if (process.argv.length > 2 && process.argv[2] === "debug") {
        SIM_OPTIONS["custom"] = SIM_OPTIONS["custom"] + " --debug";
    }

    const sim = new Zemu.default(APP_PATH);

    try {
        await sim.start(SIM_OPTIONS);
        const app = new FilecoinApp.default(sim.getTransport());

        ////////////
        /// TIP you can use zemu commands here to take the app to the point where you trigger a breakpoint

        await debugScenario2(sim, app);

        /// TIP

    } finally {
        await sim.close();
        await beforeEnd();
    }
}

(async () => {
    await main();
})();

/** Build the editable KP2 deck from slides.json using the isolated authoring runtime. */
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const required = ["ARTIFACT_TOOL_MODULE", "PRESENTATIONS_SKILL_DIR", "ARTIFACT_PYTHON",
  "RUNTIME_NODE_MODULES"];
for (const key of required) {
  if (!process.env[key]) throw new Error(`Set ${key}; see docs/kp2/build.md`);
}
const { Presentation, PresentationFile, FileBlob } = await import(
  pathToFileURL(process.env.ARTIFACT_TOOL_MODULE).href
);
const skill = process.env.PRESENTATIONS_SKILL_DIR;
const { finalizePresentation } = await import(
  pathToFileURL(path.join(skill, "container_tools/artifact_tool_utils.mjs")).href
);
const source = JSON.parse(await fs.readFile(path.join(root, "docs/kp2/slides.json"), "utf8"));
const build = path.join(root, "build/kp2", new Date().toISOString().replace(/[:.]/g, "-"));
const output = path.join(root, "deliverables/kp2/KP2_AI_Security_Gateway.pptx");
await fs.mkdir(build, { recursive: true });
await fs.mkdir(path.dirname(output), { recursive: true });
const presentation = Presentation.create({ slideSize: source.slideSize });
const color = (key) => source.colors[key] ?? key;

function text(slide, spec) {
  const shape = slide.shapes.add({
    geometry: "textbox",
    position: { left: spec.x, top: spec.y, width: spec.w, height: spec.h },
    fill: "none",
    line: { fill: "none", width: 0 },
  });
  shape.text = spec.text;
  shape.text.style = {
    typeface: source.font, fontSize: spec.size, color: color(spec.color ?? "white"),
    bold: spec.bold ?? false, insets: 0, autoFit: "none", wrap: "square",
  };
  return shape;
}

const tableSlides = [];
for (const [index, spec] of source.slides.entries()) {
  const slide = presentation.slides.add();
  slide.background.fill = source.colors.background;
  slide.hidden = spec.hidden;
  slide.speakerNotes.text = spec.notes;
  if (index > 0) text(slide, {
    text: spec.title, x: 64, y: 48, w: 1152, h: 72, size: 43, bold: true,
  });
  for (const item of spec.items) {
    if (item.type === "text") {
      text(slide, item);
    } else if (item.type === "table") {
      tableSlides.push(index + 1);
      const table = slide.tables.add({
        rows: item.values.length, columns: item.values[0].length,
        left: item.x, top: item.y, width: item.w, height: item.h,
        columnWidths: item.widths, values: item.values,
      });
      table.borders.assign({ fill: source.colors.line, width: 1, style: "solid" });
      table.cells.block({ row: 0, column: 0, rowCount: item.values.length,
        columnCount: item.values[0].length }).assign({
        fill: source.colors.background,
        textStyle: { typeface: source.font, fontSize: item.size, color: source.colors.white },
        margins: { top: 10, bottom: 10, left: 16, right: 14 },
        anchor: "center",
      });
      for (let c = 0; c < item.values[0].length; c++) {
        table.getCell(0, c).text.style = {
          typeface: source.font, fontSize: item.size, bold: true, color: source.colors.accent,
        };
      }
    } else throw new Error(`Unsupported element: ${item.type}`);
  }
  const footer = text(slide, {
    text: source.footer, x: 64, y: 682, w: 1070, h: 27, size: 20, color: "muted",
  });
  footer.text.get(source.footer).link = { uri: source.repository, isExternal: true };
  text(slide, { text: String(index + 1).padStart(2, "0"),
    x: 1160, y: 680, w: 56, h: 31, size: 22, color: "accent" });
}

const candidatePath = path.join(build, "candidate.pptx");
const finalPath = path.join(build, "output/validated.pptx");
await fs.mkdir(path.dirname(finalPath), { recursive: true });
await (await PresentationFile.exportPptx(presentation)).save(candidatePath);
await finalizePresentation({
  workspaceDir: root, candidatePath, finalPath,
  pythonExecutable: process.env.ARTIFACT_PYTHON,
  integrityValidatorPath: path.join(skill, "container_tools/inspect_presentation_package_integrity.py"),
  layoutValidatorPath: path.join(skill, "container_tools/inspect_presentation_layout_geometry.py"),
  explicitTotalSlideCount: 9,
  requiredNativeTableOwnerSlides: tableSlides,
  requiredNativeChartOwnerSlides: [],
  layoutArgs: ["--expected-slide-size-emu", "12192000,6858000",
    "--validate-bullet-geometry", "--validate-heading-fit",
    ...tableSlides.flatMap(n => ["--require-native-table-slide", String(n)])],
  fontPolicy: { basis: "design", families: [source.font] },
  verifyArtifactToolImport: true,
  receiptPath: path.join(build, "validation.json"),
});
await fs.copyFile(finalPath, output);

// Reimport the delivered bytes before rendering; these are not screenshots of the source JSON.
const finalDeck = await PresentationFile.importPptx(await FileBlob.load(output));
for (const [index, slide] of finalDeck.slides.items.entries()) {
  const stem = `slide-${String(index + 1).padStart(2, "0")}`;
  const png = await finalDeck.export({ slide, format: "png", scale: 1 });
  await fs.writeFile(path.join(build, `${stem}.png`), new Uint8Array(await png.arrayBuffer()));
  const layout = await slide.export({ format: "layout" });
  await fs.writeFile(path.join(build, `${stem}.layout.json`), await layout.text());
}
await fs.writeFile(path.join(root, "build/kp2/latest-build.txt"), build);
const markdown = ["# Содержимое презентации КП2", "",
  "Источник: [slides.json](slides.json); сборка: [build.md](build.md).",
  "7 основных слайдов + 2 скрытых приложения. Срок сдачи: 10 ноября, 23:59 МСК.",
  "2 минуты доклада + 1 минута вопросов. Вклады требуют подтверждения.", ""];
source.slides.forEach((slide, i) => {
  markdown.push(`## ${i + 1}. ${slide.title}${slide.hidden ? " (приложение)" : ""}`, "");
  for (const item of slide.items) {
    if (item.type === "text") markdown.push(item.text, "");
    else {
      markdown.push(`| ${item.values[0].join(" | ")} |`);
      markdown.push(`| ${item.values[0].map(() => "---").join(" | ")} |`);
      markdown.push(...item.values.slice(1).map(row => `| ${row.map(v => v.replaceAll("\n", " / ")).join(" | ")} |`), "");
    }
  }
  markdown.push("**Заметки / источники:**", "", slide.notes, "");
});
await fs.writeFile(path.join(root, "docs/kp2/slides.md"), markdown.join("\n"));
console.log(`Created 9 editable slides. Preview and validation: ${path.relative(root, build)}`);
console.log(path.relative(root, output));

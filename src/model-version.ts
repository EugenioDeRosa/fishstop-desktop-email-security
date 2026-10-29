/**
 * Version shown for a Fast fine-tune, read from its Ollama tag.
 * Tags carry dotted versions such as "lite-v7.1"; keep every numeric part.
 */
export function fastModelVersion(model: string): string | undefined {
  return model.match(/finetuned-lite-(v\d+(?:\.\d+)*)(?=-|$)/i)?.[1];
}

/**
 * TypeScript module declarations for proto file text imports.
 * Bun's compiled binary embeds these as string content via import assertions.
 */
declare module "*.proto" {
  const content: string;
  export default content;
}

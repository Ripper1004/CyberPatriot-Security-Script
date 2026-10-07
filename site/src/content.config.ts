import { defineCollection } from 'astro:content';
import { z } from 'astro/zod';
import { docsLoader } from '@astrojs/starlight/loaders';
import { docsSchema } from '@astrojs/starlight/schema';

export const collections = {
  docs: defineCollection({
    loader: docsLoader(),
    schema: docsSchema({
      extend: z.object({
        // Added by scripts/sync-docs.mjs
        cp: z
          .object({
            kind: z.enum(['checklist', 'lesson', 'guide', 'page']),
            id: z.string(),
            lesson: z.number().optional(),
            steps: z.number().optional(),
          })
          .optional(),
      }),
    }),
  }),
};

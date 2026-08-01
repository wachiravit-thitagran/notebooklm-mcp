#!/usr/bin/env node

import { createHash, timingSafeEqual } from 'crypto';
import http from 'http';
import https from 'https';
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';
import type { IncomingHttpHeaders, IncomingMessage, ServerResponse
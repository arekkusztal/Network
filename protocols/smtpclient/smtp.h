/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2016 Arek Kusztal. All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *	 * Redistributions of source code must retain the above copyright
 *	   notice, this list of conditions and the following disclaimer.
 *	 * Redistributions in binary form must reproduce the above copyright
 *	   notice, this list of conditions and the following disclaimer in
 *	   the documentation and/or other materials provided with the
 *	   distribution.
 *	 * Neither the name of Network Project nor the names of its
 *	   contributors may be used to endorse or promote products derived
 *	   from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*** SMTP header file */
/* RFC 821 */
/* RFC 2821 */

#ifndef SMTP_UTILS_H
#define SMTP_UTILS_H


/*** Response params */
#define HELP_REPLY		"221"
#define HELP_MESSAGE 	"214"
#define SRV_READY		"220"
#define SRV_CLOSING		"221"
#define RQ_MAIL_OK		"250"
#define FORWARD			"251"
#define START_INPUT		"354"
#define SRV_NAN			"421"
#define MBOX_UNAVAIL	"450"
#define ABORTED			"451"
#define INSUFFISIANT	"452"
#define SYNTAX_ERR		"500"
#define BAD_ARG			"501"
#define NOT_IMPL		"502"
#define BAD_SEQ			"503"
#define PARAM_NOT_IMPL  "504"
#define NOT_FOUND		"550"
#define USER_NOT_LOCAL	"551"
#define MAIL_ABORTED	"552"
#define NOT_ALLOWED		"553"
#define TRAN_FAILED		"554"

/* Config -- adding space at the end */

#define EHLO 	"EHLO "
#define HELO 	"HELO "
#define HELO 	"MAIL "

struct smtp_cmd {
	uint8_t cmd[5];
    uint8_t param[507];
};

struct SMTP_response {
    uint8_t cmd[4];
    uint8_t param[];
};

struct smtp_resp {
	uint8_t cmd[4];
    uint8_t param[508];
};

extern const char B_64[];

#define CRLF	"\r\n"

uint32_t
SMTP_strlen(uint8_t *msg);
int
host_to_ip(uint8_t *ip, uint8_t *name);
uint8_t *
strtbase64(uint8_t *msg, uint32_t sz);

#endif

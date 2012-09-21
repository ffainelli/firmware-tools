/*
 * Prints a "PID" file which can be obtained from the unlapbind utility
 *
 * Copyright (C) 2012, Florian Fainelli <florian@openwrt.org>
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/stat.h>

struct pid_field {
	const char *name;
	unsigned int size;
};

static struct pid_field pid_fields[] = {
	{ "Version control", 4 },
	{ "Down control", 4 },
	{ "Hardware ID", 64 },
	{ "Hardware version", 4 },
	{ "Prod ID", 4 },
	{ "Prod ID mask", 4 },
	{ "Prot ID", 4 },
	{ "Prot ID mask", 4 },
	{ "Func ID", 4 },
	{ "Func ID mask", 4 },
	{ "Firmware Version", 4 },
	{ "C segment", 4 },
	{ "C size", 4 },
};

#define ARRAY_SIZE(x)	(sizeof((x)) / sizeof((x[0])))

int main(int argc, char **argv)
{
	int ret;
	struct stat st;
	char buf[PID_SIZE];
	FILE *fp;
	size_t i;
	char formatter[255];
	unsigned int offset = 0;

	ret = stat(argv[1], &st);
	if (ret < 0) {
		perror("stat");
		return ret;
	}

	if (st.st_size != PID_SIZE) {
		fprintf(stderr, "invalid file size: %ld\n", st.st_size);
		return 1;
	}

	fp = fopen(argv[1], "rb");
	if (!fp) {
		perror("fopen");
		return 1;
	}

	fread(buf, PID_SIZE, 1, fp);
	fclose(fp);

	for (i = 0; i < ARRAY_SIZE(pid_fields); i++) {
		sprintf(formatter, "%%.%ds\n", pid_fields[i].size);
		fprintf(stdout, "%s: ", pid_fields[i].name);
		fprintf(stdout, formatter, buf + offset);
		offset += pid_fields[i].size;
	}

	return 0;
}

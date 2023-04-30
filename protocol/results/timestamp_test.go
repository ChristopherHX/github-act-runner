package results

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTimestampFormat(t *testing.T) {
	table := []struct {
		Input  string
		Output string
	}{
		{
			Input:  "2023-04-30T20:33:46Z",
			Output: "2023-04-30T20:33:46.000Z",
		},
		{
			Input:  "2023-04-30T20:33:46.907Z",
			Output: "2023-04-30T20:33:46.907Z",
		},
		{
			Input:  "2023-04-30T22:50:13.916+02:00",
			Output: "2023-04-30T22:50:13.916+02:00",
		},
	}

	for _, i := range table {
		stamp, err := time.Parse(TimestampInputFormat, i.Input)
		assert.NoError(t, err)
		assert.NotNil(t, stamp)
		assert.Equal(t, i.Output, stamp.Format(TimestampOutputFormat))
	}
}

func TestConvertTimestamp(t *testing.T) {
	table := []struct {
		Input  string
		Output string
	}{
		{
			Input:  "2023-04-30T20:33:46Z",
			Output: "2023-04-30T20:33:46.000Z",
		},
		{
			Input:  "2023-04-30T20:33:46.9070001Z",
			Output: "2023-04-30T20:33:46.907Z",
		},
		{
			Input:  "2023-04-30T22:50:13.91657+02:00",
			Output: "2023-04-30T22:50:13.916+02:00",
		},
	}

	for _, i := range table {
		assert.Equal(t, i.Output, ConvertTimestamp(i.Input))
	}
}
